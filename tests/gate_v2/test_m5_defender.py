"""Defender adapter status and path-generation regression cases."""

from __future__ import annotations

import subprocess
import hashlib
import time
from pathlib import Path

import pytest

from sentinel.gate_v2.contract import ScanRequest, StageStatus, Strength, VerdictCode
from sentinel.gate_v2.core import CoreAdapter
from sentinel.gate_v2.defender import DefenderAdapter
from sentinel.gate_v2.orchestrator import scan


def request(path: Path, seconds: float = 5) -> ScanRequest:
    return ScanRequest(2, "m5", "file", str(path), None, "test", "single_file",
                       "evidence-v1", "evidence-v1",
                       time.monotonic_ns() + int(seconds * 1e9), None, False)


def run(path: Path, runner, *, active: bool = True):
    engine = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active" if active else "passive"), runner=runner)
    return scan(request(path), adapters=[engine], gate_generation="m5",
                auto_quarantine=False, skip_after_conclusive=False)


@pytest.mark.parametrize("code,output,status", [
    (0, "Scan completed", StageStatus.COMPLETED),
    (2, "Threat : Virus:DOS/EICAR_Test_File", StageStatus.COMPLETED),
    (2, "Scan failed", StageStatus.ERROR),
    (1, "Scan failed", StageStatus.ERROR),
    (7, "Threat : Named.Bad", StageStatus.ERROR),
    (2, "Threat : <bad>", StageStatus.ERROR),
    (0, "\ufffd", StageStatus.ERROR),
    (0, "x" * 65537, StageStatus.ERROR),
])
def test_runner_matrix(tmp_path: Path, code: int, output: str, status: StageStatus) -> None:
    path = tmp_path / "harmless.bin"
    path.write_bytes(b"ordinary synthetic bytes")
    calls = []
    def fake(argv, deadline, cancel):
        calls.append((argv, deadline))
        return code, output
    decision = run(path, fake)
    result = decision.engine_results[0]
    assert result.status is status
    assert calls[0][0] == ["MpCmdRun.exe", "-Scan", "-ScanType", "3", "-File",
                           str(path), "-DisableRemediation"]
    assert calls[0][1] <= request(path).deadline_monotonic_ns
    if code == 2 and status is StageStatus.COMPLETED:
        assert result.evidence[0].strength is Strength.CONCLUSIVE
        assert result.evidence[0].raw_name == "Virus:DOS/EICAR_Test_File"
        assert decision.verdict is VerdictCode.MALICIOUS
    elif status is StageStatus.COMPLETED:
        assert result.verdict is VerdictCode.CLEAN
        assert decision.verdict is VerdictCode.CLEAN
    else:
        assert decision.verdict is VerdictCode.UNKNOWN
        assert not result.evidence
        assert output not in str(result.to_dict())


def test_timeout_and_oserror(tmp_path: Path) -> None:
    path = tmp_path / "harmless.bin"
    path.write_bytes(b"ordinary")
    def timeout(argv, deadline, cancel):
        assert deadline > time.monotonic_ns()
        raise subprocess.TimeoutExpired(argv, 0.01)
    assert run(path, timeout).engine_results[0].status is StageStatus.TIMEOUT
    late_calls = []
    def late(argv, deadline, cancel):
        late_calls.append(deadline)
        time.sleep(max(0, (deadline - time.monotonic_ns()) / 1e9) + 0.01)
        return 0, "Scan completed"
    engine = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active"), runner=late)
    delayed = scan(request(path, 0.25), adapters=[engine], gate_generation="m5",
                   auto_quarantine=False)
    assert late_calls
    assert delayed.engine_results[0].status is StageStatus.TIMEOUT
    def missing(argv, deadline, cancel):
        raise OSError("private runner text")
    result = run(path, missing).engine_results[0]
    assert result.status is StageStatus.UNAVAILABLE
    assert "private runner text" not in str(result.to_dict())


def test_passive_never_runs_and_ttl(tmp_path: Path) -> None:
    path = tmp_path / "harmless.bin"
    path.write_bytes(b"ordinary")
    calls = []
    def applicability(_):
        calls.append(1)
        return "MpCmdRun.exe", "passive"
    engine = DefenderAdapter(applicability=applicability,
                             runner=lambda *args: pytest.fail("passive runner called"))
    first = scan(request(path), adapters=[engine], gate_generation="m5", auto_quarantine=False)
    second = scan(request(path), adapters=[engine], gate_generation="m5", auto_quarantine=False)
    assert len(calls) == 1
    assert first.engine_results[0].status is StageStatus.UNAVAILABLE
    assert first.engine_results[0].readiness_code == "PASSIVE"
    assert second.verdict is VerdictCode.UNKNOWN


def test_not_installed_and_scan_cap(tmp_path: Path) -> None:
    path = tmp_path / "harmless.bin"
    path.write_bytes(b"ordinary")
    missing = DefenderAdapter(applicability=lambda _: (None, "unknown"),
                              runner=lambda *args: pytest.fail("missing runner called"))
    unavailable = scan(request(path), adapters=[missing], gate_generation="m5",
                       auto_quarantine=False).engine_results[0]
    assert unavailable.status is StageStatus.UNAVAILABLE
    assert unavailable.readiness_code == "NOT_INSTALLED"
    seen = []
    def fake(argv, deadline, cancel):
        seen.append(deadline)
        return 0, "Scan completed"
    ready = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active"), runner=fake)
    began = time.monotonic_ns()
    scan(request(path, 120), adapters=[ready], gate_generation="m5",
         auto_quarantine=False)
    assert seen and seen[0] <= began + 90_100_000_000


def test_swapped_before_defender_stage(tmp_path: Path) -> None:
    path = tmp_path / "harmless.bin"
    path.write_bytes(b"first synthetic generation")
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"other synthetic generation")
    class Swap(CoreAdapter):
        def scan_bound(self, request, measured, cancel, reader):
            found = super().scan_bound(request, measured, cancel, reader)
            moved = path.with_name("old.bin")
            path.rename(moved)
            replacement.rename(path)
            return found
    defender = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active"),
                               runner=lambda *args: pytest.fail("changed path scanned"))
    decision = scan(request(path), adapters=[Swap(), defender], gate_generation="m5",
                    auto_quarantine=False, skip_after_conclusive=False)
    assert decision.engine_results[1].status is StageStatus.CHANGED
    assert decision.verdict is VerdictCode.UNKNOWN


def test_swapped_during_defender_stage(tmp_path: Path) -> None:
    path = tmp_path / "harmless.bin"
    path.write_bytes(b"first synthetic generation")
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"other synthetic generation")
    def swapped(argv, deadline, cancel):
        moved = path.with_name("old.bin")
        path.rename(moved)
        replacement.rename(path)
        return 0, "Scan completed"
    decision = run(path, swapped)
    assert decision.engine_results[0].status is StageStatus.CHANGED
    assert decision.verdict is VerdictCode.UNKNOWN


def test_named_hit_with_clean_companion(tmp_path: Path) -> None:
    path = tmp_path / "harmless.bin"
    path.write_bytes(b"ordinary synthetic bytes")
    defender = DefenderAdapter(applicability=lambda _: ("MpCmdRun.exe", "active"),
                               runner=lambda *_: (2, "Threat : Named.Detection"))
    decision = scan(request(path), adapters=[CoreAdapter(), defender],
                    gate_generation="m5", auto_quarantine=False)
    assert decision.engine_results[0].verdict is VerdictCode.CLEAN
    assert decision.verdict is VerdictCode.MALICIOUS
    assert decision.accepted_evidence_ids == ("defender." + hashlib.sha256(b"Named.Detection").hexdigest()[:24],)
