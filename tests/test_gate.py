"""The multi-engine scan gate: ClamAV protocol, layer statuses, cache keys, scan jobs, YARA feed.

A fake clamd on localhost stands in for the real one so these tests run
anywhere; `test_real_clamav_*` talk to a real clamd and are skipped when
none is running (start one with `sentinel clamav start`).
"""

from __future__ import annotations

import os
import socket
import struct
import threading
import time

import pytest

from conftest import EICAR, MARKER
from sentinel.engine import clamav
from sentinel.engine.clamav import ClamAVEngine, finding_for, parse_reply
from sentinel.engine.scanner import Scanner
from sentinel.engine.signatures import _yara_severity
from sentinel.engine.verdict import CLEAN, MALICIOUS, SUSPICIOUS, Severity
from sentinel.scanjob import ScanJob


class FakeClamd:
    """Speaks enough of clamd's protocol: PING, VERSION, INSTREAM."""

    def __init__(self, verdict=lambda data: "OK", version: str = "ClamAV 1.5.4/1/test") -> None:
        self.verdict = verdict
        self.version = version
        self.streams: list[bytes] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    self._handle(conn)
                except OSError:
                    pass

    def _read_exact(self, conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            part = conn.recv(n - len(buf))
            if not part:
                raise OSError("closed")
            buf += part
        return buf

    def _handle(self, conn: socket.socket) -> None:
        cmd = b""
        while not cmd.endswith(b"\0"):
            cmd += self._read_exact(conn, 1)
        if cmd == b"zPING\0":
            conn.sendall(b"PONG\0")
        elif cmd == b"zVERSION\0":
            conn.sendall(self.version.encode() + b"\0")
        elif cmd == b"zINSTREAM\0":
            data = b""
            while True:
                (n,) = struct.unpack(">I", self._read_exact(conn, 4))
                if n == 0:
                    break
                data += self._read_exact(conn, n)
            self.streams.append(data)
            conn.sendall(f"stream: {self.verdict(data)}\0".encode())

    def close(self) -> None:
        self._stop = True
        self.sock.close()


@pytest.fixture
def fake_clamd():
    srv = FakeClamd(verdict=lambda d: "Win.Test.Fake-1 FOUND" if MARKER in d else "OK")
    yield srv
    srv.close()


def gate(db, srv: FakeClamd) -> Scanner:
    return Scanner(db, use_defender=False, clamav_engine=ClamAVEngine(autostart=False, port_=srv.port))


# -- protocol --------------------------------------------------------------

@pytest.mark.parametrize("reply,expected", [
    ("stream: OK", ("ok", None)),
    ("stream: Win.Test.EICAR_HDB-1 FOUND", ("found", "Win.Test.EICAR_HDB-1")),
    ("stream: Heuristics.Encrypted.Zip FOUND", ("found", "Heuristics.Encrypted.Zip")),
    ("INSTREAM size limit exceeded. ERROR", ("error", "INSTREAM size limit exceeded. ERROR")),
    ("", ("error", "empty reply")),
])
def test_parse_reply(reply, expected):
    assert parse_reply(reply) == expected


def test_heuristic_and_pua_names_are_never_conclusive():
    assert finding_for("Win.Trojan.Agent-1").severity == Severity.CRITICAL
    assert finding_for("Heuristics.Phishing.Email").severity == Severity.MEDIUM
    assert finding_for("PUA.Win.Tool.Foo").severity == Severity.MEDIUM


# -- gate behaviour --------------------------------------------------------

def test_clamav_detection_makes_file_malicious(db, fake_clamd, tmp_path):
    p = tmp_path / "payload.bin"
    p.write_bytes(b"\x00\x01" + MARKER)  # no rule pack loaded: only ClamAV can see it
    v = gate(db, fake_clamd).scan_file(p)
    assert v.label == MALICIOUS
    assert v.engines["clamav"] == "detected"
    assert v.engines["sentinel"] == "clean"
    assert any(f.engine == "clamav" for f in v.findings)


def test_clamav_receives_exactly_the_hashed_bytes(db, fake_clamd, tmp_path):
    p = tmp_path / "doc.txt"
    p.write_bytes(b"A" * 700_000)  # several INSTREAM chunks
    v = gate(db, fake_clamd).scan_file(p)
    assert v.label == CLEAN and v.engines["clamav"] == "clean"
    assert fake_clamd.streams[-1] == b"A" * 700_000


def test_layers_are_reported_even_when_clean(db, fake_clamd, tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("hello")
    v = gate(db, fake_clamd).scan_file(p)
    assert set(v.engines) == {"sentinel", "rules+yara", "clamav", "defender"}
    assert v.to_dict()["engines"] == v.engines


def test_clamav_down_is_reported_not_silently_clean(db, tmp_path):
    srv = FakeClamd()
    port = srv.port
    srv.close()  # nothing listens there now
    p = tmp_path / "a.txt"
    p.write_text("hello")
    v = Scanner(db, use_defender=False, clamav_engine=ClamAVEngine(autostart=False, port_=port)).scan_file(p)
    assert v.engines["clamav"].startswith("unavailable")


def test_clamav_error_reply_is_recorded(db, tmp_path):
    srv = FakeClamd(verdict=lambda d: "Can't allocate memory ERROR")
    try:
        p = tmp_path / "a.txt"
        p.write_text("hello")
        v = gate(db, srv).scan_file(p)
        assert v.engines["clamav"].startswith("error")
        assert v.label == CLEAN  # an engine failure is not evidence of malware
    finally:
        srv.close()


def test_clamav_heuristic_alone_is_only_suspicious(db, tmp_path):
    srv = FakeClamd(verdict=lambda d: "Heuristics.Broken.Executable FOUND")
    try:
        p = tmp_path / "a.txt"
        p.write_text("hello")
        assert gate(db, srv).scan_file(p).label == SUSPICIOUS
    finally:
        srv.close()


def test_files_over_the_clamav_limit_get_their_front_scanned(db, fake_clamd, monkeypatch, tmp_path):
    from sentinel import config

    monkeypatch.setattr(config, "MAX_DEEP_SCAN_BYTES", 500)
    monkeypatch.setattr(clamav, "STREAM_MAX_BYTES", 1000)
    p = tmp_path / "big.bin"
    p.write_bytes(b"x" * 2000)
    v = gate(db, fake_clamd).scan_file(p)
    assert v.engines["clamav"].startswith("partial")
    assert fake_clamd.streams == [b"x" * 1000]
    p.write_bytes(MARKER + b"\x00" * 3000)  # payload up front, padding behind it
    assert gate(db, fake_clamd).scan_file(p).engines["clamav"] == "detected"


def test_oversized_file_rules_see_front_and_tail(scanner, monkeypatch, tmp_path):
    from sentinel import config

    monkeypatch.setattr(config, "MAX_DEEP_SCAN_BYTES", 4096)
    p = tmp_path / "padded.dat"
    p.write_bytes(b"\x00" * 20_000 + MARKER)  # appended payload
    v = scanner.scan_file(p)
    assert v.label == MALICIOUS and v.engines["rules+yara"] == "detected"


def test_padded_executable_is_suspicious(scanner, monkeypatch, tmp_path):
    from sentinel import config
    from sentinel.engine import scanner as scanner_mod

    monkeypatch.setattr(config, "MAX_DEEP_SCAN_BYTES", 4096)
    monkeypatch.setattr(scanner_mod, "INFLATED_PE_BYTES", 1024 * 1024)
    p = tmp_path / "setup.exe"
    p.write_bytes(b"MZ" + os.urandom(8000) + b"\x00" * (3 * 1024 * 1024))
    v = scanner.scan_file(p)
    assert any(f.rule == "pe.inflated" for f in v.findings) and v.label == SUSPICIOUS
    p.write_bytes(b"MZ" + os.urandom(3 * 1024 * 1024))  # compressed overlay: an ordinary installer
    assert not any(f.rule == "pe.inflated" for f in scanner.scan_file(p).findings)


def test_large_file_is_streamed_from_disk(db, fake_clamd, monkeypatch, tmp_path):
    from sentinel import config

    monkeypatch.setattr(config, "MAX_DEEP_SCAN_BYTES", 1024)  # force the "too big for memory" path
    p = tmp_path / "big.bin"
    p.write_bytes(b"\x00" * 5000 + MARKER)
    v = gate(db, fake_clamd).scan_file(p)
    assert v.skipped and "hash and name" in v.skipped
    assert v.engines["clamav"] == "detected" and v.label == MALICIOUS


def test_cached_verdict_is_not_reused_after_clamav_update(db, tmp_path):
    srv = FakeClamd(version="ClamAV 1.5.4/100/old")
    try:
        p = tmp_path / "x.bin"
        p.write_bytes(b"\x00" + MARKER)
        sc = gate(db, srv)
        assert sc.scan_file(p).label == CLEAN  # old database: no signature yet
        assert sc.scan_file(p).label == CLEAN and len(srv.streams) == 1  # served from cache
        srv.version = "ClamAV 1.5.4/101/new"
        srv.verdict = lambda d: "Win.Test.New-1 FOUND"
        sc.clamav._version = None  # skip the 60 s version cache
        assert sc.scan_file(p).label == MALICIOUS
    finally:
        srv.close()


def test_trusted_hash_skips_every_layer(db, fake_clamd, tmp_path):
    import hashlib

    p = tmp_path / "tool.bin"
    p.write_bytes(b"\x00" + MARKER)
    db.allow_hash(hashlib.sha256(p.read_bytes()).hexdigest())
    v = gate(db, fake_clamd).scan_file(p)
    assert v.label == CLEAN and "allowlist" in v.engines
    assert fake_clamd.streams == []


def test_scan_bytes_also_asks_clamav(db, fake_clamd):
    v = gate(db, fake_clamd).scan_bytes(b"zz" + MARKER, "mem.bin")
    assert v.engines["clamav"] == "detected" and v.label == MALICIOUS


# -- scan jobs -------------------------------------------------------------

def test_scan_job_counts_and_quarantines(db, fake_clamd, tmp_path):
    from sentinel.config import Settings

    root = tmp_path / "tree"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "evil.dat").write_bytes(MARKER)
    for i in range(5):
        (root / f"ok{i}.txt").write_text("fine")
    results = []
    job = ScanJob(gate(db, fake_clamd), db, Settings(), [str(root)], "t",
                  on_result=lambda v, o: results.append((v, o))).start()
    job.join(30)
    p = job.progress
    assert not p.running and p.scanned == 6 and p.detections == 1 and p.quarantined == 1
    assert p.unverified == 0
    assert not (root / "a" / "b" / "evil.dat").exists()
    assert results[0][0]["engines"]["clamav"] == "detected"


def test_scan_job_without_external_engines_counts_unverified(db, tmp_path):
    from sentinel.config import Settings

    (tmp_path / "x.txt").write_text("fine")
    job = ScanJob(Scanner(db, use_defender=False), db, Settings(), [str(tmp_path)], "t").start()
    job.join(30)
    assert job.progress.scanned == 1 and job.progress.unverified == 1


def test_scan_job_can_be_cancelled(db, tmp_path):
    from sentinel.config import Settings

    for i in range(300):
        (tmp_path / f"f{i}.txt").write_text("x")
    job = ScanJob(Scanner(db, use_defender=False), db, Settings(), [str(tmp_path)], "t")
    job.cancel()
    job.start().join(30)
    assert job.progress.cancelled and job.progress.scanned == 0


def test_scan_job_skips_agent_data_dir(db, sentinel_home):
    from sentinel.config import Settings

    (sentinel_home / "quarantine").mkdir(exist_ok=True)
    (sentinel_home / "quarantine" / "x.qbin").write_bytes(MARKER)
    job = ScanJob(Scanner(db, use_defender=False), db, Settings(), [str(sentinel_home.parent)], "t").start()
    job.join(30)
    assert job.progress.detections == 0


# -- YARA ------------------------------------------------------------------

def test_yara_forge_score_maps_to_severity():
    assert _yara_severity({"score": 90}) == Severity.HIGH
    assert _yara_severity({"score": 70}) == Severity.MEDIUM
    assert _yara_severity({"score": 40}) == Severity.LOW
    assert _yara_severity({"severity": "critical", "score": 10}) == Severity.CRITICAL
    assert _yara_severity({}) == Severity.HIGH


def test_yara_feed_drops_only_rules_that_do_not_compile(sentinel_home):
    pytest.importorskip("yara_x")
    import io
    import zipfile

    from sentinel import yarafeed

    src = ('import "pe"\n'
           'rule good_one { meta: score = 85 strings: $a = "SENTINEL-YARA-OK" condition: $a }\n'
           'rule broken { condition: no_such_identifier }\n'
           'private rule helper { strings: $h = "HELPER-XYZ" condition: $h }\n'
           'rule uses_helper { condition: helper }\n')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("packages/core/yara-rules-core.yar", src)
    assert yarafeed.update(fetch=lambda url: buf.getvalue()) == "ok: 3 rules, 1 not supported by YARA-X"

    from sentinel.db import Database

    sc = Scanner(Database(), use_defender=False)
    assert sc.sigs.yara_rules == 3
    v = sc.scan_bytes(b"xx SENTINEL-YARA-OK xx", "a.txt")
    assert any(f.rule == "yara.good_one" and f.severity == Severity.HIGH for f in v.findings)
    assert v.engines["rules+yara"] == "detected"
    assert any(f.rule == "yara.uses_helper" for f in sc.scan_bytes(b"HELPER-XYZ", "b.txt").findings)


# -- real ClamAV (skipped if no clamd) --------------------------------------

def _real_clamd() -> ClamAVEngine:
    eng = ClamAVEngine(autostart=False, port_=clamav.DEFAULT_PORT)
    if not eng.client.ping():
        pytest.skip("no clamd running (sentinel clamav start)")
    return eng


def _containers(payload: bytes, member: str = "docs/invoice.pdf.exe") -> dict[str, bytes]:
    """The same test payload wrapped the ways malware is delivered; all built in memory."""
    import base64
    import bz2
    import gzip
    import io
    import lzma
    import tarfile
    import zipfile

    out: dict[str, bytes] = {"raw": payload}
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(member, payload)
    out["zip"] = z.getvalue()
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", out["zip"])
    out["zip-in-zip"] = outer.getvalue()
    t = io.BytesIO()
    with tarfile.open(fileobj=t, mode="w:gz") as tf:
        ti = tarfile.TarInfo("setup.com")
        ti.size = len(payload)
        tf.addfile(ti, io.BytesIO(payload))
    out["tar.gz"] = t.getvalue()
    out["gzip"] = gzip.compress(payload)
    out["bzip2"] = bz2.compress(payload)
    out["xz"] = lzma.compress(payload)
    out["mime-attachment"] = (
        b"From: a@example.invalid\r\nTo: b@example.invalid\r\nSubject: invoice\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
        b"--XX\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"a.com\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.encodebytes(payload) + b"\r\n--XX--\r\n")
    return out


def test_real_clamav_detects_eicar_in_every_container(db):
    eng = _real_clamd()
    sc = Scanner(db, use_defender=False, clamav_engine=eng)
    missed = []
    for kind, blob in _containers(EICAR).items():
        v = sc.scan_bytes(blob, f"sample.{kind}")
        if v.label != MALICIOUS or v.engines.get("clamav") != "detected":
            missed.append((kind, v.engines.get("clamav")))
    assert missed == []


def test_real_clamav_keeps_clean_containers_clean(db):
    eng = _real_clamd()
    sc = Scanner(db, use_defender=False, clamav_engine=eng)
    for kind, blob in _containers(b"just an ordinary invoice, nothing to see " * 20, "docs/invoice.pdf").items():
        v = sc.scan_bytes(blob, f"sample.{kind}")
        assert v.engines.get("clamav") == "clean", kind


def test_real_clamav_flags_disguised_executable_name_in_zip(db):
    # ClamAV has container-metadata signatures: a ZIP whose member is named
    # "*.pdf.exe" is flagged even when the member's bytes are harmless.
    eng = _real_clamd()
    blob = _containers(b"harmless bytes " * 20)["zip"]
    v = Scanner(db, use_defender=False, clamav_engine=eng).scan_bytes(blob, "invoice.zip")
    assert v.engines["clamav"] == "detected"


def test_real_clamav_answers_quickly(db):
    eng = _real_clamd()
    t = time.monotonic()
    for _ in range(20):
        eng.scan_bytes(b"x" * 10_000)
    assert time.monotonic() - t < 10


# -- self-attack regressions ----------------------------------------------

def test_cache_is_not_fooled_by_same_size_swap_with_restored_mtime(scanner, tmp_path):
    p = tmp_path / "tool.bin"
    p.write_bytes(b"A" * (len(MARKER) + 4))
    st = p.stat()
    assert scanner.scan_file(p).label == CLEAN
    p.write_bytes(b"BBBB" + MARKER)
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert p.stat().st_size == st.st_size and p.stat().st_mtime_ns == st.st_mtime_ns
    assert scanner.scan_file(p).label == MALICIOUS
