"""Regressions for the second M5 review, using harmless synthetic input."""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel.gate_v2.analyzers.lnk import LnkAdapter, MAX_LNK
from sentinel.gate_v2.analyzers.motw import MotwAdapter, read_zone
from sentinel.gate_v2.analyzers.signer import SignerAdapter, win_verify_trust
from sentinel.gate_v2.content import BoundReader
from sentinel.gate_v2.contract import ByteRange, Category, Coverage, ScanRequest, StageStatus, Strength, VerdictCode
from sentinel.gate_v2.core import CoreAdapter
from sentinel.gate_v2.defender import DefenderAdapter, MAX_OUTPUT, _Cancelled, _applicability, _run
from sentinel.gate_v2.identity import measure_bytes
from sentinel.gate_v2.orchestrator import scan
from sentinel.gate_v2.policy import RequiredStages, decide


def request(path: Path | None = None, data: bytes | None = None, seconds: float = 5) -> ScanRequest:
    return ScanRequest(2, "m5-r2", "file", str(path) if path else None, data, "test",
                       "single_file", "evidence-v1", "evidence-v1",
                       time.monotonic_ns() + int(seconds * 1e9), None, False)


def defender(path: Path, output: str, *, code: int = 2, seconds: float = 5):
    adapter = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active"),
                              runner=lambda *_: (code, output))
    return scan(request(path, seconds=seconds), adapters=[adapter], gate_generation="r2",
                auto_quarantine=False, skip_after_conclusive=False)


def link(*, flags: int, strings: tuple[str, ...] = (), info: bytes = b"",
         idlist: bytes = b"", extra: bytes = b"") -> bytes:
    body = bytearray(76)
    body[:4] = (76).to_bytes(4, "little")
    body[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    body[20:24] = flags.to_bytes(4, "little")
    if flags & 1:
        body += len(idlist).to_bytes(2, "little") + idlist
    if flags & 2:
        body += info
    for value in strings:
        body += len(value).to_bytes(2, "little") + value.encode("utf-16le")
    return bytes(body) + extra


def direct(adapter, data: bytes):
    measured = measure_bytes(data).identity
    assert measured is not None
    reader = BoundReader.from_bytes(data, measured)
    return adapter.scan_bound(request(data=data), measured, type("T", (), {"cancelled": lambda self: False})(), reader)


def test_k1_multiple_duplicate_invalid_names_and_limit(tmp_path: Path) -> None:
    path = tmp_path / "ordinary.bin"
    path.write_bytes(b"ordinary")
    d = defender(path, "Threat : Named.One\nThreat : Named.One\nThreat : <bad>\nThreat : Named.Two")
    hits = d.engine_results[0].evidence
    assert [e.raw_name for e in hits] == ["Named.One", "Named.Two"]
    assert len({e.evidence_id for e in hits}) == 2
    assert hits[0].evidence_id == "defender." + hashlib.sha256(b"Named.One").hexdigest()[:24]
    assert d.verdict is VerdictCode.MALICIOUS
    limited = defender(path, "\n".join(f"Threat : Named.{i}" for i in range(17))).engine_results[0]
    assert len(limited.evidence) == 16
    assert "THREAT_NAME_LIMIT" in limited.coverage.limits_hit


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object")
def test_k2_k15_runner_bytes_and_output_limit() -> None:
    class Token:
        def cancelled(self): return False
    deadline = time.monotonic_ns() + 5_000_000_000
    code, output = _run([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'T\\xe0i');sys.exit(3)"], deadline, Token())
    assert (code, output) == (3, "Tà i".replace(" ", ""))
    _, output = _run([sys.executable, "-c", f"print('x' * {MAX_OUTPUT + 1})"], deadline, Token())
    assert output == "\0"
    with pytest.raises(subprocess.TimeoutExpired):
        _run([sys.executable, "-c", "import time;time.sleep(30)"], time.monotonic_ns() + 100_000_000, Token())


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object")
@pytest.mark.parametrize("cancel_run", [False, True])
def test_k15_job_kills_grandchild(tmp_path: Path, cancel_run: bool) -> None:
    marker = tmp_path / "grandchild_marker.txt"
    spawned = tmp_path / "spawned.txt"
    child_code = ("import pathlib,time;time.sleep(2);"
                  f"pathlib.Path({str(marker)!r}).write_text('ran')")
    parent_code = ("import pathlib,subprocess,sys,time;"
                   f"subprocess.Popen([sys._base_executable,'-c',{child_code!r}]);"
                   f"pathlib.Path({str(spawned)!r}).write_text('started');"
                   "time.sleep(30)")
    event = threading.Event()
    class Token:
        def cancelled(self): return event.is_set()
    if cancel_run:
        def cancel_after_spawn():
            for _ in range(100):
                if spawned.exists():
                    event.set()
                    return
                time.sleep(0.02)
        threading.Thread(target=cancel_after_spawn, daemon=True).start()
    deadline = time.monotonic_ns() + (5_000_000_000 if cancel_run else 1_000_000_000)
    with pytest.raises(_Cancelled if cancel_run else subprocess.TimeoutExpired):
        _run([sys.executable, "-c", parent_code], deadline, Token())
    assert spawned.exists()
    time.sleep(2.1)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="WinVerifyTrust")
def test_k15_wintrust_with_open_handle() -> None:
    import msvcrt
    with open(sys._base_executable, "rb") as stream:
        state = win_verify_trust(sys._base_executable, msvcrt.get_osfhandle(stream.fileno()))
    if state == "unavailable":
        pytest.skip("WinVerifyTrust unavailable on this host")
    assert state in {"valid", "unsigned", "invalid", "revoked"}


def test_k3_k4_named_hit_survives_change_and_deadline(tmp_path: Path) -> None:
    path = tmp_path / "ordinary.bin"
    path.write_bytes(b"first")
    def changed(*_):
        moved = path.with_name("old.bin")
        path.rename(moved)
        path.write_bytes(b"second")
        return 2, "Threat : Named.One"
    adapter = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active"), runner=changed)
    d = scan(request(path), adapters=[adapter], gate_generation="r2", auto_quarantine=True)
    assert d.engine_results[0].status is StageStatus.CHANGED
    assert d.engine_results[0].evidence and d.verdict is VerdictCode.UNKNOWN
    assert "UNACCEPTED_DETECTION" in d.reason_codes
    assert not d.cacheable and not d.action_decision.quarantine
    def late(*_):
        time.sleep(0.03)
        return 2, "Threat : Named.Two"
    adapter = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active"), runner=late)
    d = scan(request(path, seconds=0.01), adapters=[adapter], gate_generation="r2", auto_quarantine=False)
    assert d.engine_results[0].evidence


def test_k5_k6_context_rule_and_name_policy(tmp_path: Path) -> None:
    from sentinel.gate_v2.policy import classify_defender_name
    path = tmp_path / "ordinary.bin"
    path.write_bytes(b"ordinary")
    assert classify_defender_name("PUA:Win32/Example") == (Category.PUA, Strength.SUPPORTING)
    assert classify_defender_name("HackTool:Win32/Example") == (Category.RISKWARE, Strength.SUPPORTING)
    assert classify_defender_name("Named.One") == (Category.MALWARE, Strength.CONCLUSIVE)
    assert defender(path, "Threat : EICAR_Test_File").engine_results[0].evidence[0].is_test_file
    for name in ("PUA:Win32/Example", "HackTool:Win32/Example"):
        d = defender(path, "Threat : " + name)
        assert d.verdict is VerdictCode.SUSPICIOUS
    data = link(flags=8 | 32 | 0x80, strings=("cmd.exe", "/c harmless"))
    d = scan(request(data=data), adapters=[CoreAdapter(), LnkAdapter()],
             gate_generation="r2", auto_quarantine=True)
    assert d.verdict is VerdictCode.SUSPICIOUS
    assert "CONTEXT_RULE" in d.reason_codes and not d.trusted_clean
    assert not d.action_decision.quarantine
    motw = MotwAdapter(reader=lambda _: "[ZoneTransfer]\nHostUrl=https://blocked.invalid/a",
                       url_check=lambda url: "blocked" in url)
    d = scan(request(path), adapters=[CoreAdapter(), motw], gate_generation="r2", auto_quarantine=True)
    assert d.verdict is VerdictCode.SUSPICIOUS
    assert any(e.detail_code == "ORIGIN_BLOCKLISTED" and not e.ranges
               for e in d.engine_results[-1].evidence)
    assert "blocked.invalid" not in str(d.to_dict())


def test_k10_k11_link_candidates_and_partial() -> None:
    assert direct(LnkAdapter(), b"ordinary").readiness_code == "NOT_LNK"
    assert direct(LnkAdapter(), b"ordinary" * 128).coverage.inspected == (ByteRange(0, 76),)
    padded = link(flags=8 | 32 | 0x80, strings=("cmd.exe", " " * 5000 + "/c harmless"))
    assert direct(LnkAdapter(), padded).evidence
    clipped = link(flags=8 | 32 | 0x80, strings=("cmd.exe", " " * 9000 + "/c harmless"))
    observed = direct(LnkAdapter(), clipped)
    assert observed.evidence and observed.coverage.mode == "fixed_partial"
    assert direct(LnkAdapter(), clipped + b"x" * MAX_LNK).evidence
    info = bytearray(64)
    info[:4] = (64).to_bytes(4, "little")
    info[4:8] = (28).to_bytes(4, "little")
    info[16:20] = (28).to_bytes(4, "little")
    info[24:28] = (40).to_bytes(4, "little")
    info[28:40] = b"cmd.exe\0\0\0\0\0"
    info[40:49] = b"test.txt\0"
    assert direct(LnkAdapter(), link(flags=2 | 8 | 32 | 0x80, info=bytes(info),
                                     strings=("note.txt", "/c harmless"))).evidence
    unicode_info = bytearray(128)
    unicode_info[:4] = (128).to_bytes(4, "little")
    unicode_info[4:8] = (36).to_bytes(4, "little")
    unicode_info[28:32] = (36).to_bytes(4, "little")
    unicode_info[36:52] = "cmd.exe\0".encode("utf-16le")
    assert direct(LnkAdapter(), link(flags=2 | 32 | 0x80, info=bytes(unicode_info),
                                     strings=("/c harmless",))).evidence
    assert direct(LnkAdapter(), link(flags=1 | 32 | 0x80, idlist=b"cmd.exe",
                                     strings=("/c harmless",))).evidence
    env = bytearray(788)
    env[:4] = len(env).to_bytes(4, "little")
    env[4:8] = (0xA0000001).to_bytes(4, "little")
    env[8:16] = b"cmd.exe\0"
    assert direct(LnkAdapter(), link(flags=32 | 0x80, strings=("/c harmless",),
                                     extra=bytes(env))).evidence


def test_k7_stage_ranges_are_local(tmp_path: Path) -> None:
    path = tmp_path / "ordinary.bin"
    path.write_bytes(b"x" * (2 * 1024 * 1024))
    d = scan(request(path), adapters=[CoreAdapter(), SignerAdapter()],
             gate_generation="r2", auto_quarantine=False)
    assert d.engine_results[1].coverage.inspected == (ByteRange(0, 4096),)


def test_k8_busy_trust_returns_promptly() -> None:
    entered = threading.Event()
    release = threading.Event()
    class Token:
        def cancelled(self): return False
    def hang(*_):
        entered.set()
        release.wait(2)
        return "valid"
    first = SignerAdapter(trust=hang)
    thread = threading.Thread(target=lambda: first._bounded_trust("file", 1,
                               time.monotonic_ns() + 2_000_000_000, Token()))
    thread.start()
    assert entered.wait(1)
    try:
        start = time.monotonic()
        assert SignerAdapter()._bounded_trust("file", 1, time.monotonic_ns() + 1_000_000_000, Token()) == "unavailable"
        assert time.monotonic() - start < 0.5
    finally:
        release.set()
        thread.join(2)


def test_k9_revalidation_is_bounded_and_motw_metadata_only(tmp_path: Path, monkeypatch) -> None:
    from sentinel.gate_v2 import identity
    path = tmp_path / "ordinary.bin"
    path.write_bytes(b"ordinary")
    original = identity.revalidate
    calls = []
    def record(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)
    monkeypatch.setattr(identity, "revalidate", record)
    adapter = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active"),
                              runner=lambda *_: (0, "Scan completed"))
    scan(request(path), adapters=[adapter], gate_generation="r2",
         auto_quarantine=False, max_bytes=100)
    assert len(calls) >= 3
    assert all(call.get("cancel") is not None for call in calls)
    assert all(call["max_bytes"] == 100 for call in calls if call["rehash"])
    calls.clear()
    scan(request(path), adapters=[MotwAdapter(reader=lambda _: None)],
         gate_generation="r2", auto_quarantine=False)
    assert calls and all(call["rehash"] is False for call in calls)


def test_k12_motw_absence_error_and_blocklist(tmp_path: Path) -> None:
    path = tmp_path / "ordinary"
    path.write_bytes(b"ordinary")
    absent = scan(request(path), adapters=[MotwAdapter(reader=lambda _: None)],
                  gate_generation="r2", auto_quarantine=False).engine_results[0]
    assert absent.status is StageStatus.COMPLETED and absent.readiness_code == "NO_ORIGIN"
    def fail(_):
        raise PermissionError("denied")
    error = scan(request(path), adapters=[MotwAdapter(reader=fail)],
                 gate_generation="r2", auto_quarantine=False).engine_results[0]
    assert error.status is StageStatus.ERROR and error.readiness_code == "MOTW_READ_ERROR"
    def check(_):
        raise RuntimeError("unavailable")
    observed = scan(request(path), adapters=[MotwAdapter(reader=lambda _: "[ZoneTransfer]\nHostUrl=https://example.invalid",
                                                     url_check=check)],
                    gate_generation="r2", auto_quarantine=False).engine_results[0]
    assert "URL_CHECK_ERROR" in observed.coverage.limits_hit


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate data stream")
def test_k12_utf16_zone_stream(tmp_path: Path) -> None:
    path = tmp_path / "ordinary"
    path.write_bytes(b"ordinary")
    with open(str(path) + ":Zone.Identifier", "wb") as stream:
        stream.write("[ZoneTransfer]\nZoneId=3".encode("utf-16"))
    assert "ZoneId=3" in read_zone(str(path))


def test_k13_declared_coverage_exception(tmp_path: Path) -> None:
    from sentinel.gate_v2.policy import _DECLARED_COVERAGE_ENGINES
    assert _DECLARED_COVERAGE_ENGINES == frozenset({"defender"})
    path = tmp_path / "ordinary"
    path.write_bytes(b"ordinary")
    d = defender(path, "Scan completed", code=0)
    assert d.trusted_clean
    r = d.engine_results[0]
    other = replace(r, engine_id="other")
    q = request(path)
    assert "UNCERTAIN_COVERAGE" in decide((other,), q, "r2", stages=RequiredStages(frozenset({"other"}))).reason_codes
    limited = replace(r, coverage=replace(r.coverage, mode="fixed_partial", limits_hit=("LIMIT",)))
    assert not decide((limited,), q, "r2", stages=RequiredStages(frozenset({"defender"}))).trusted_clean
    opaque = replace(r, coverage=replace(r.coverage, mode="fixed_partial", objects_seen=1,
                                         objects_opaque=1))
    assert not decide((opaque,), q, "r2", stages=RequiredStages(frozenset({"defender"}))).trusted_clean


def test_k16_unknown_applicability_retry_clock(tmp_path: Path) -> None:
    path = tmp_path / "ordinary"
    path.write_bytes(b"ordinary")
    times = [0]
    calls = []
    def applicable(deadline):
        calls.append(deadline)
        return "MpCmdRun.exe", "unknown"
    adapter = DefenderAdapter(applicability=applicable, clock=lambda: times[0])
    assert adapter.readiness() == "APPLICABILITY_UNKNOWN"
    assert adapter.readiness() == "APPLICABILITY_UNKNOWN"
    assert len(calls) == 1
    times[0] = 31_000_000_000
    adapter.readiness()
    assert len(calls) == 2


def test_k16_cancel_during_applicability_probe() -> None:
    entered = threading.Event()
    release = threading.Event()
    cancelled = threading.Event()
    def probe(_):
        entered.set()
        release.wait(2)
        return "MpCmdRun.exe", "active"
    adapter = DefenderAdapter(applicability=probe)
    class Token:
        def cancelled(self): return cancelled.is_set()
    threading.Timer(0.1, cancelled.set).start()
    try:
        start = time.monotonic()
        assert adapter._applicable(time.monotonic_ns() + 1_000_000_000, Token())[1] == "unknown"
        assert entered.is_set() and time.monotonic() - start < 0.5
    finally:
        release.set()


@pytest.mark.skipif(os.name != "nt", reason="Windows Defender path discovery")
def test_k16_numeric_platform_order_and_absolute_powershell(monkeypatch) -> None:
    from sentinel.gate_v2 import defender as module
    paths = [r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.9999\MpCmdRun.exe",
             r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25000\MpCmdRun.exe"]
    monkeypatch.setattr(module.glob, "glob", lambda _: paths)
    monkeypatch.setattr(module.os.path, "isfile", lambda _: True)
    seen = []
    def fake(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "4096\n", "")
    monkeypatch.setattr(module.subprocess, "run", fake)
    exe, state = _applicability(time.monotonic_ns() + 2_000_000_000)
    assert exe == paths[1] and state == "active"
    assert os.path.isabs(seen[0][0])


def test_k17_defender_pool_serializes(tmp_path: Path) -> None:
    path = tmp_path / "ordinary"
    path.write_bytes(b"ordinary")
    entered = threading.Event()
    release = threading.Event()
    def slow(*_):
        entered.set()
        release.wait(2)
        return 0, "Scan completed"
    first = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active"), runner=slow)
    second = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active"),
                             runner=lambda *_: pytest.fail("pool not serialized"))
    thread = threading.Thread(target=lambda: scan(request(path), adapters=[first],
                                                  gate_generation="r2", auto_quarantine=False))
    thread.start()
    assert entered.wait(1)
    try:
        d = scan(request(path, seconds=0.1), adapters=[second], gate_generation="r2",
                 auto_quarantine=False)
        assert d.engine_results[0].status is StageStatus.TIMEOUT
    finally:
        release.set()
        thread.join(2)


def test_k17_uses_measured_canonical_path(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path("ordinary").write_bytes(b"ordinary")
    seen = []
    adapter = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active"),
                              runner=lambda argv, *_: (seen.append(argv) or 0, "Scan completed"))
    scan(request(Path("ordinary")), adapters=[adapter], gate_generation="r2", auto_quarantine=False)
    assert seen and os.path.isabs(seen[0][5])
