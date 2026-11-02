from __future__ import annotations

import hashlib
import io
import json
import struct
import time
from pathlib import Path

import pytest

from conftest import MARKER
from sentinel import config, feeds, quarantine, urlintel
from sentinel.nativehost import Host, read_message, write_message
from sentinel.protection import act_on


# -- quarantine ----------------------------------------------------------------

def test_quarantine_roundtrip(db, scanner, tmp_path):
    p = tmp_path / "bad.bin"
    content = b"head " + MARKER + b" tail"
    p.write_bytes(content)
    v = scanner.scan_file(p)
    out = act_on(db, v, config.Settings(), "scan")
    assert out["quarantined"] and not p.exists()
    blob = (config.quarantine_dir() / f"{out['quarantine_id']}.qbin").read_bytes()
    assert MARKER not in blob  # stored inert
    assert db.events(5)[0]["level"] == "threat"

    restored = quarantine.restore(db, out["quarantine_id"])
    assert restored.read_bytes() == content
    assert db.is_hash_allowed(hashlib.sha256(content).hexdigest())
    assert db.quarantine_items() == []
    # Once trusted, the same file is no longer flagged.
    assert scanner.scan_file(restored).label == "clean"


def test_no_quarantine_when_disabled(db, scanner, tmp_path):
    p = tmp_path / "bad.bin"
    p.write_bytes(MARKER)
    s = config.Settings()
    s.auto_quarantine = False
    out = act_on(db, scanner.scan_file(p), s, "scan")
    assert not out["quarantined"] and p.exists()


# -- url intel -----------------------------------------------------------------

def test_normalize_url():
    assert urlintel.normalize_url("HTTPS://Example.COM:443/a?b=1#frag") == "https://example.com/a?b=1"
    assert urlintel.normalize_url("http://example.com:8080") == "http://example.com:8080/"
    assert urlintel.normalize_url("ftp://example.com/") is None
    assert urlintel.normalize_url("not a url") is None


def test_parent_host_match_and_allowlist(db):
    db.add_hosts([("evil.example", "phishing", "test")])
    assert urlintel.check(db, "https://login.evil.example/x")["verdict"] == "malicious"
    assert urlintel.check(db, "https://notevil.example/")["verdict"] == "unknown"
    db.allow_host("login.evil.example")
    assert urlintel.check(db, "https://login.evil.example/x")["verdict"] == "allowed"


def test_url_level_match(db):
    db.add_urls([("https://drive.google.com/file/d/abc/view", "malware", "test")])
    assert urlintel.check(db, "https://drive.google.com/file/d/abc/view#x")["verdict"] == "malicious"
    assert urlintel.check(db, "https://drive.google.com/file/d/other/view")["verdict"] == "unknown"


def test_registrable_domain():
    assert urlintel.registrable_domain("a.b.example.com") == "example.com"
    assert urlintel.registrable_domain("www.vietcombank.com.vn") == "vietcombank.com.vn"
    assert urlintel.registrable_domain("10.0.0.1") == "10.0.0.1"


# -- feeds ---------------------------------------------------------------------

HOSTS_TEXT = """# comment
0.0.0.0 bad-one.example
bad-two.example
raw.githubusercontent.com
docs.google.com
not_a_host
"""


def test_parse_hosts_skips_shared_platforms_and_junk():
    hosts = list(feeds.parse_hosts(HOSTS_TEXT))
    assert hosts == ["bad-one.example", "bad-two.example"]


def _run(db, feeds_list, texts, fail=()):
    def fetcher(url):
        if url in fail:
            raise OSError("network down")
        return texts[url]
    return feeds.update_all(db, feeds_list, fetcher=fetcher)


def test_popular_domains_are_never_host_blocked(db):
    db.set_popular(["wikipedia.org", "example-popular.com"])
    f = feeds.Feed("t", "u", "bad_hosts", "phishing", feeds.parse_hosts)
    _run(db, [f], {"u": "sub.example-popular.com\nreal-bad.example\n"})
    assert db.host_info("sub.example-popular.com") is None
    assert db.host_info("real-bad.example") is not None


def test_phishing_url_feed_also_blocks_dedicated_hosts(db):
    f = feeds.Feed("op", "u", "bad_urls", "phishing", feeds.parse_urls)
    _run(db, [f], {"u": "https://paypa1-login.example/signin\nhttps://sites.google.com/view/lure\n"})
    assert db.host_info("paypa1-login.example") is not None
    assert db.host_info("sites.google.com") is None
    assert db.url_info("https://sites.google.com/view/lure") is not None


def test_feed_failure_is_isolated_and_keeps_old_data(db):
    good = feeds.Feed("good", "u-good", "bad_hosts", "malware", feeds.parse_hosts)
    bad = feeds.Feed("bad", "u-bad", "bad_hosts", "malware", feeds.parse_hosts)
    urls = feeds.Feed("op", "u-urls", "bad_urls", "phishing", feeds.parse_urls)
    _run(db, [good, bad, urls], {"u-good": "kept.example\n", "u-bad": "kept-bad.example\n",
                                 "u-urls": "https://lure.example/x\n"})
    # Next run: one feed is offline, one serves an error page, one parses nothing.
    res = _run(db, [good, bad, urls], {"u-good": "<html>error page</html>", "u-urls": ""}, fail={"u-bad"})
    assert all(v.startswith("error") for v in res.values())
    assert db.host_info("kept.example") is not None
    assert db.host_info("kept-bad.example") is not None
    assert db.url_info("https://lure.example/x") is not None
    assert db.host_info("lure.example") is not None
    assert {f["name"]: f["status"][:5] for f in db.feed_status()} == {"good": "error", "bad": "error", "op": "error"}


def test_feed_replace_drops_delisted(db):
    f = feeds.Feed("rot", "u", "bad_hosts", "malware", feeds.parse_hosts)
    _run(db, [f], {"u": "old.example\nstays.example\n"})
    _run(db, [f], {"u": "stays.example\n"})
    assert db.host_info("old.example") is None and db.host_info("stays.example") is not None


def test_snapshot_swap_and_cleanup(db):
    from sentinel import indicators

    f = feeds.Feed("s", "u", "bad_hosts", "malware", feeds.parse_hosts)
    for i in range(3):
        _run(db, [f], {"u": f"gen{i}.example\n"})
    files = list(indicators.snapshot_dir().glob("indicators-*.db"))
    assert len(files) <= 2  # superseded snapshots are deleted once closed
    assert db.host_info("gen2.example") is not None and db.host_info("gen0.example") is None
    assert db.counts()["bad_hosts"] == 1


def test_tranco_parsing_limits():
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("top-1m.csv", "".join(f"{i},site{i}.example\n" for i in range(1, 2001)))
    assert feeds.parse_tranco(buf.getvalue(), top=1000)[:2] == ["site1.example", "site2.example"]
    with pytest.raises(ValueError):
        feeds.parse_tranco(buf.getvalue(), top=100_000)  # truncated list is rejected


def test_blocked_hosts_priority_order(db):
    db.add_hosts([("z-threat.example", "threat", "a"), ("y-malware.example", "malware", "b"),
                  ("x-phish.example", "phishing", "c")])
    assert [h for h, _ in db.blocked_hosts(limit=2)] == ["y-malware.example", "x-phish.example"]


# -- native host -----------------------------------------------------------------

def _frame(obj) -> bytes:
    data = json.dumps(obj).encode()
    return struct.pack("<I", len(data)) + data


def test_native_framing_roundtrip():
    out = io.BytesIO()
    write_message(out, {"id": 1, "ok": True, "x": "đã chặn"})
    out.seek(0)
    assert read_message(out) == {"id": 1, "ok": True, "x": "đã chặn"}
    assert read_message(io.BytesIO(b"")) is None
    assert read_message(io.BytesIO(struct.pack("<I", 5) + b"{bad}")) == {"type": "__bad_json__"}


def test_native_handlers(db, marker_rule, tmp_path):
    db.add_hosts([("phish.example", "phishing", "test")])
    host = Host(db, config.Settings(use_defender=False))
    assert host.handle({"id": 1, "type": "hello"})["ok"]
    r = host.handle({"id": 2, "type": "check_url", "url": "https://a.phish.example/login"})
    assert r["ok"] and r["result"]["verdict"] == "malicious" and r["id"] == 2
    assert not host.handle({"id": 3, "type": "check_url", "url": 42})["ok"]
    assert not host.handle({"id": 4, "type": "nope"})["ok"]
    assert not host.handle(["not", "an", "object"])["ok"]
    assert not host.handle({"type": "report", "action": "evil", "url": "https://x/"})["ok"]
    assert not host.handle({"type": "scan_download", "path": "relative.exe"})["ok"]
    assert not host.handle({"type": "allow_host", "host": "a b/c"})["ok"]

    page = host.handle({"type": "get_blocklist", "offset": 0, "limit": 1})
    assert page["total"] == 1 and page["hosts"] == [["phish.example", "phishing"]]

    p = tmp_path / "download.bin"
    p.write_bytes(MARKER)
    r = host.handle({"type": "scan_download", "path": str(p), "url": "https://phish.example/f"})
    assert r["ok"] and r["verdict"]["label"] == "malicious" and r["quarantined"]
    assert r["url_reputation"]["verdict"] == "malicious"


# -- real-time watcher -----------------------------------------------------------

def test_watcher_quarantines_new_file(db, scanner, tmp_path):
    pytest.importorskip("watchdog")
    from sentinel.watcher import RealtimeProtection

    watched = tmp_path / "watched"
    watched.mkdir()
    s = config.Settings(watch_dirs=[str(watched)], use_defender=False)
    results = []
    rt = RealtimeProtection(db, s, scanner, on_result=results.append)
    rt.start()
    try:
        time.sleep(0.5)
        (watched / "partial.crdownload").write_bytes(MARKER)  # ignored while downloading
        (watched / "clean.txt").write_bytes(b"just text")
        bad = watched / "dropped.bin"
        bad.write_bytes(b"x" + MARKER)
        deadline = time.time() + 15
        while time.time() < deadline and bad.exists():
            time.sleep(0.2)
    finally:
        rt.stop()
    assert not bad.exists(), "malicious file was not quarantined in time"
    assert (watched / "clean.txt").exists()
    assert any(r["quarantined"] for r in results)
    assert all(not r["verdict"]["path"].endswith(".crdownload") for r in results)


def test_run_key_command_files(tmp_path):
    from sentinel.watcher import command_files

    script = tmp_path / "payload.ps1"
    script.write_text("x")
    dll = tmp_path / "lib.dll"
    dll.write_text("x")
    cmd = f'powershell.exe -NoProfile -File "{script}"'
    assert str(script) in command_files(cmd)
    assert str(dll) in command_files(f"rundll32.exe {dll},Entry")


def test_run_key_command_target():
    from sentinel.watcher import command_target

    assert command_target('"C:\\Program Files\\App\\app.exe" --min') == "C:\\Program Files\\App\\app.exe"
    assert command_target("C:\\Tools\\tool.exe /silent") == "C:\\Tools\\tool.exe"


# -- report --------------------------------------------------------------------

def test_report_writes_html_and_json(db, tmp_path):
    db.add_event("web", "threat", "Đã chặn", "<script>x</script>")
    from sentinel import report

    paths = report.write_report(db, config.Settings(), tmp_path / "out")
    html = Path(paths["html"]).read_text(encoding="utf-8")
    assert "Báo cáo Sentinel Guard" in html and "<script>x</script>" not in html
    assert json.loads(Path(paths["json"]).read_text(encoding="utf-8"))["threats"]
