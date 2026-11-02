"""Regression tests for Codex review round 2 (see REVIEWS.md)."""

from __future__ import annotations

import io
import os
import sqlite3
import struct
import zipfile
from pathlib import Path

import pytest

from sentinel import feeds


def _run(db, feeds_list, texts, fail=()):
    def fetcher(url):
        if url in fail:
            raise OSError("network down")
        return texts[url]
    return feeds.update_all(db, feeds_list, fetcher=fetcher)


def test_damaged_header_is_repaired_when_opening(sentinel_home):
    from sentinel.db import Database

    p = sentinel_home / "sentinel.db"
    p.write_bytes(b"not a database at all" * 100)
    db = Database()  # must not raise
    assert db.repaired_from and Path(db.repaired_from).exists()
    db.add_event("system", "info", "works", "after repair")
    moved = db.check_and_repair()  # reports the repair done at open, once
    assert moved and Path(moved).exists()
    assert db.check_and_repair() is None


def test_v1_upgrade_keeps_protection(sentinel_home):
    from sentinel.db import Database

    db = Database()
    db.close()
    # Recreate a v1 layout: feed rows inside the state DB, no snapshot.
    c = sqlite3.connect(sentinel_home / "sentinel.db", isolation_level=None)
    c.execute("INSERT INTO bad_hosts VALUES('legacy-bad.example','phishing','phishing_filter',0)")
    c.execute("INSERT INTO bad_hosts VALUES('mine.example','custom','user',0)")
    c.execute("UPDATE meta SET value='1' WHERE key='schema_version'")
    c.execute("DELETE FROM meta WHERE key='indicators_file'")
    c.close()
    db = Database()
    assert db.host_info("legacy-bad.example") is not None  # now served from the snapshot
    assert db._exec("SELECT COUNT(*) AS n FROM bad_hosts WHERE source='phishing_filter'").fetchone()["n"] == 0
    assert db.host_info("mine.example") is not None  # user entries stay local


def test_host_listed_by_two_feeds_survives_delist_plus_failure(db):
    a = feeds.Feed("a", "ua", "bad_hosts", "malware", feeds.parse_hosts)
    b = feeds.Feed("b", "ub", "bad_hosts", "phishing", feeds.parse_hosts)
    _run(db, [a, b], {"ua": "shared.example\n", "ub": "shared.example\nonly-b.example\n"})
    assert db.host_info("shared.example")["kind"] == "malware"  # highest priority kind wins
    # a delists it, b is offline: b's own copy is carried over.
    _run(db, [a, b], {"ua": "other.example\n"}, fail={"ub"})
    row = db.host_info("shared.example")
    assert row is not None and row["source"] == "b"
    assert db.counts()["bad_hosts"] == 3


def test_carry_over_respects_new_popular_list(db):
    a = feeds.Feed("a", "ua", "bad_hosts", "malware", feeds.parse_hosts)
    _run(db, [a], {"ua": "becomes-popular.example\nstill-bad.example\n"})
    db.set_popular(["becomes-popular.example"])
    _run(db, [a], {}, fail={"ua"})
    assert db.host_info("becomes-popular.example") is None
    assert db.host_info("still-bad.example") is not None


def test_user_block_survives_repair_and_unblock_is_scoped(sentinel_home):
    from sentinel.db import Database

    db = Database()
    db.add_hosts([("my-block.example", "custom", "user"), ("ioc.example", "malware", "analyst")])
    assert not db.remove_local_host("ioc.example")  # not the user's entry
    assert db.host_info("ioc.example") is not None
    moved = db._rebuild()  # the repair path, deterministically
    assert Path(moved).exists()
    assert db.host_info("my-block.example") is not None  # user's own block is salvaged
    assert db.host_info("ioc.example") is None  # other local rows are not
    assert db.remove_local_host("my-block.example")


def test_zip_declaring_huge_directory_is_not_opened(scanner):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "x")
    data = bytearray(buf.getvalue())
    i = data.rfind(b"PK\x05\x06")
    data[i + 8:i + 12] = struct.pack("<HH", 0xFFFF, 0xFFFF)  # entries on disk / total
    data[i + 12:i + 16] = struct.pack("<I", 0xFFFFFF00)  # directory size
    v = scanner.scan_bytes(bytes(data), "lying.zip")
    assert any(f.rule == "archive.directory_too_large" for f in v.findings)


def test_format1_snapshot_is_still_served(db):
    from sentinel import indicators

    # Layout written before per-feed rows existed: hosts keyed by host, no `best`.
    p = indicators.snapshot_dir() / "indicators-old-format.db"
    c = sqlite3.connect(p)
    c.executescript("""
        CREATE TABLE hosts (host TEXT PRIMARY KEY, kind TEXT, source TEXT, rank INTEGER);
        CREATE TABLE urls (url TEXT PRIMARY KEY, kind TEXT, source TEXT);
        CREATE TABLE hashes (sha256 TEXT PRIMARY KEY, source TEXT, name TEXT);
        CREATE TABLE popular (domain TEXT PRIMARY KEY);
        CREATE TABLE info (key TEXT PRIMARY KEY, value TEXT);
        INSERT INTO hosts VALUES ('old-format-bad.example', 'phishing', 'phishing_filter', 1);
        INSERT INTO info VALUES ('count_hosts', '1');
    """)
    c.commit()
    c.close()
    db.set_meta(indicators.POINTER_KEY, str(p))
    db.indicators.refresh()
    assert db.host_info("old-format-bad.example") is not None
    assert db.blocked_hosts() == [("old-format-bad.example", "phishing")]
    assert db.indicators.outdated
    assert feeds.is_due(db, 1000)  # forces a rebuild in the new format


def test_counters_are_monotonic(db):
    assert [db._increment("x") for _ in range(3)] == [1, 2, 3]
    before = db.allow_version()
    db.allow_host("t.example")
    db.remove_allowed_host("t.example")
    assert int(db.allow_version()) == int(before) + 2


@pytest.mark.skipif(os.name != "nt", reason="named kernel objects are Windows-only")
def test_app_lock_is_global_and_per_data_dir(sentinel_home):
    from sentinel.singleton import NamedLock

    lock = NamedLock("Tray")
    assert lock.name.startswith("Global\\SentinelGuard.")
    assert lock.acquire()
    lock.release()


def test_configured_feeds_adds_hash_feed_only_with_key():
    from sentinel.config import Settings

    assert not any(f.name == "malwarebazaar" for f in feeds.configured_feeds(Settings()))
    with_key = feeds.configured_feeds(Settings(abusech_auth_key="k"))
    mb = next(f for f in with_key if f.name == "malwarebazaar")
    assert dict(mb.headers) == {"Auth-Key": "k"}
