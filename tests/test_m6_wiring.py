"""Gate v2 behind Scanner: what wiring it in must not change, and what it must fix."""

from __future__ import annotations

import io
import os
import zipfile

import pytest

from conftest import MARKER
from sentinel import config
from sentinel.engine.clamav import ClamAVEngine
from sentinel.engine.scanner import Scanner
from sentinel.engine.verdict import CLEAN, MALICIOUS, SUSPICIOUS, Finding, Severity
from sentinel.gate_v2.clamd import DatabaseFacts
from sentinel.gate_v2.legacy import UNKNOWN
from sentinel.protection import act_on
from sentinel.scanjob import ScanJob
from sentinel.watcher import RETRY_DELAYS, ScanQueue
from test_gate import FakeClamd, gate


@pytest.fixture
def clamd_says():
    servers: list[FakeClamd] = []

    def start(reply: str) -> FakeClamd:
        servers.append(FakeClamd(verdict=lambda data: reply))
        return servers[-1]

    yield start
    for server in servers:
        server.close()


def file_with(tmp_path, data: bytes = b"ordinary bytes", name: str = "a.bin"):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_legacy_v0_still_quarantines_a_weak_clamav_name(db, tmp_path, clamd_says):
    # The label improves (RT-001) but the action policy is the owner's locked
    # decision: only evidence-v1 stops this quarantine.
    p = file_with(tmp_path)
    v = gate(db, clamd_says("Win.Trojan.Suspect-34 FOUND")).scan_file(p)
    assert v.label == SUSPICIOUS
    assert act_on(db, v, config.Settings(), "scan")["quarantined"]
    assert not p.exists()


def test_auto_quarantine_off_is_still_honoured(db, tmp_path, clamd_says):
    p = file_with(tmp_path)
    v = gate(db, clamd_says("Win.Trojan.Real-1 FOUND")).scan_file(p)
    settings = config.Settings()
    settings.auto_quarantine = False
    assert v.label == MALICIOUS and not act_on(db, v, settings, "scan")["quarantined"]
    assert p.exists()


def test_a_process_squatting_the_clamd_port_is_not_believed(db, tmp_path, clamd_says):
    # The fake is not clamd.exe: with the real check its OK clears nothing, and
    # its FOUND cannot quarantine.
    p = file_with(tmp_path)
    for reply, label in (("OK", UNKNOWN), ("Win.Trojan.Real-1 FOUND", UNKNOWN)):
        srv = clamd_says(reply)
        engine = ClamAVEngine(autostart=False, port_=srv.port,
                              facts=lambda: DatabaseFacts(True, True, "1", "inventory", "config", True, None))
        v = Scanner(db, use_defender=False, clamav_engine=engine).scan_file(p, use_cache=False)
        assert v.label == label, reply
        assert not act_on(db, v, config.Settings(), "scan")["quarantined"]
    assert p.exists()


def test_stale_signatures_do_not_clear_a_file(db, tmp_path, clamd_says):
    from datetime import datetime, timedelta, timezone

    srv = clamd_says("OK")
    old = datetime.now(timezone.utc) - timedelta(days=30)
    engine = ClamAVEngine(autostart=False, port_=srv.port, verifier=lambda _: True,
                          facts=lambda: DatabaseFacts(True, True, "1", "inventory", "config", True, old))
    assert Scanner(db, use_defender=False, clamav_engine=engine).scan_file(file_with(tmp_path)).label == UNKNOWN


def test_a_declared_certificate_does_not_read_as_a_detection(db, tmp_path):
    body = bytearray(4096)
    body[:2] = b"MZ"
    body[0x3c:0x40] = (0x80).to_bytes(4, "little")
    body[0x80:0x84] = b"PE\0\0"
    body[0x94:0x96] = (224).to_bytes(2, "little")
    body[0x98:0x9a] = (0x10b).to_bytes(2, "little")
    entry = 0x98 + 96 + 32
    body[entry:entry + 4] = (3000).to_bytes(4, "little")
    body[entry + 4:entry + 8] = (16).to_bytes(4, "little")
    v = Scanner(db, use_defender=False).scan_file(file_with(tmp_path, bytes(body), "signed.exe"))
    assert v.label == CLEAN and v.engines["sentinel"] == "clean"


@pytest.mark.skipif(os.name != "nt", reason="alternate data stream")
def test_a_download_from_a_blocklisted_source_is_suspicious(db, tmp_path):
    p = file_with(tmp_path, name="tool.dat")
    with open(str(p) + ":Zone.Identifier", "w", encoding="utf-8") as stream:
        stream.write("[ZoneTransfer]\nZoneId=3\nHostUrl=https://bad.invalid/tool.dat\n")
    db.add_hosts([("bad.invalid", "malware", "user")])
    v = Scanner(db, use_defender=False).scan_file(p)
    assert v.label == SUSPICIOUS and any(f.rule == "origin.blocklisted_source" for f in v.findings)
    assert not act_on(db, v, config.Settings(), "scan")["quarantined"]


def test_a_hidden_stream_is_not_called_clean(db, tmp_path):
    if os.name != "nt":
        pytest.skip("alternate data stream")
    p = file_with(tmp_path)
    with open(str(p) + ":payload", "wb") as stream:
        stream.write(b"synthetic bytes outside the main stream")
    assert Scanner(db, use_defender=False).scan_file(p).label == UNKNOWN


def test_a_cached_decision_never_skips_the_action_or_strengthens(db, tmp_path, clamd_says):
    srv = clamd_says("OK")
    scanner = gate(db, srv)
    p = file_with(tmp_path)
    first = scanner.scan_file(p)
    second = scanner.scan_file(p)
    assert first.label == second.label == CLEAN and len(srv.streams) == 1
    assert second.decision.action_decision is not None
    assert second.to_dict()["scan_result"]["trusted_clean"] is first.to_dict()["scan_result"]["trusted_clean"]
    assert scanner.scan_file(p, use_cache=False).label == CLEAN and len(srv.streams) == 2


def test_an_unknown_file_is_not_counted_as_a_threat(db, tmp_path, clamd_says):
    (tmp_path / "tree").mkdir()
    file_with(tmp_path / "tree")
    job = ScanJob(gate(db, clamd_says("Can't allocate memory ERROR")), db, config.Settings(),
                  [str(tmp_path / "tree")], "t").start()
    job.join(30)
    assert (job.progress.unknown, job.progress.detections, job.progress.quarantined) == (1, 0, 0)


def test_the_watcher_retries_and_then_reports_a_count(db, scanner):
    queue = ScanQueue(scanner, db, config.Settings())
    queue._incomplete("a.bin", len(RETRY_DELAYS) - 1)
    assert queue._pending["a.bin"].attempts == len(RETRY_DELAYS)
    queue._pending.clear()
    for name in ("a.bin", "b.bin", "c.bin"):
        queue._incomplete(name, len(RETRY_DELAYS))
    queue._report_incomplete()
    queue._report_incomplete()
    events = [e for e in db.events() if e["title"] == "Có tệp chưa kiểm tra xong"]
    assert len(events) == 1 and '"files": 3' in events[0]["data"]


def test_a_url_verdict_added_after_the_scan_still_quarantines(db, tmp_path, scanner):
    # Owner question 2 is open, so nativehost keeps today's behaviour.
    p = file_with(tmp_path)
    v = scanner.scan_file(p)
    assert v.label == CLEAN
    v.findings.append(Finding("origin", "origin.blocklisted_download", Severity.CRITICAL, "listed", 100))
    assert v.label == MALICIOUS and act_on(db, v, config.Settings(), "download")["quarantined"]


def test_old_archive_signals_survive(db):
    scanner = Scanner(db, use_defender=False)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("setup.exe", b"harmless synthetic bytes")
    data = bytearray(buffer.getvalue())
    for signature, flag in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = data.find(signature)
        data[at + flag:at + flag + 2] = (1).to_bytes(2, "little")
    v = scanner.scan_bytes(bytes(data), "locked.zip")
    assert any(f.rule == "archive.encrypted_executable" for f in v.findings)
    assert v.label == SUSPICIOUS


def test_files_above_the_limit_are_reported_not_clean(db, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MAX_SCAN_BYTES", 8)
    v = Scanner(db, use_defender=False).scan_file(file_with(tmp_path, MARKER))
    assert v.label == UNKNOWN and v.skipped == "too large to scan"
