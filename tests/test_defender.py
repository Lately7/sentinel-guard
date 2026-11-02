"""Defender layer: every outcome is typed, and only a completed scan is "clean" (RT-008)."""

from __future__ import annotations

import subprocess

import pytest

from sentinel.engine import defender
from sentinel.engine.scanner import Scanner
from sentinel.engine.verdict import MALICIOUS

THREAT_OUTPUT = "Scanning C:\\x found 1 threats.\n\nThreat                  : Virus:DOS/EICAR_Test_File\n"
FAILED_OUTPUT = "[Failed][0x80004005] Unspecified error\nCmdTool: Failed with hr = 0x80004005."
# A harmless PE-looking file: makes Defender's "risky type" check fire without any real code.
FAKE_EXE = b"MZ" + b"\0" * 510


def runner_returning(code: int, out: str) -> defender.Runner:
    return lambda argv, timeout: (code, out)


def runner_raising(exc: BaseException) -> defender.Runner:
    def run(argv: list[str], timeout: float) -> tuple[int, str]:
        raise exc
    return run


@pytest.fixture
def fake_mpcmdrun(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(defender, "mpcmdrun_path", lambda: r"C:\fake\MpCmdRun.exe")
    monkeypatch.setattr(defender, "available", lambda: True)


@pytest.mark.parametrize("runner, status", [
    (runner_returning(0, ""), "clean"),
    (runner_returning(2, THREAT_OUTPUT), "malicious"),
    (runner_returning(2, FAILED_OUTPUT), "error"),
    (runner_returning(5, ""), "error"),
    (runner_raising(subprocess.TimeoutExpired(["MpCmdRun"], 90)), "timeout"),
    (runner_raising(OSError("access denied")), "error"),
])
def test_scan_outcomes_are_typed(tmp_path, fake_mpcmdrun, runner, status):
    f = tmp_path / "a.exe"
    f.write_bytes(FAKE_EXE)
    res = defender.scan(str(f), runner=runner)
    assert res.status == status
    assert (res.engine_status == "clean") == (status == "clean")
    assert bool(res.findings) == (status == "malicious")


def test_missing_mpcmdrun_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(defender, "mpcmdrun_path", lambda: None)
    f = tmp_path / "a.exe"
    f.write_bytes(FAKE_EXE)
    assert defender.scan(str(f), runner=runner_returning(0, "")).status == "unavailable"


def test_vanished_file_is_an_error_not_clean(tmp_path, fake_mpcmdrun):
    res = defender.scan(str(tmp_path / "gone.exe"), runner=runner_returning(0, ""))
    assert res.status == "error"


@pytest.mark.parametrize("runner, expected", [
    (runner_raising(subprocess.TimeoutExpired(["MpCmdRun"], 90)), "timeout"),
    (runner_returning(2, FAILED_OUTPUT), "error"),
])
def test_scanner_never_records_a_failed_defender_scan_as_clean(db, tmp_path, fake_mpcmdrun, runner, expected):
    f = tmp_path / "setup.exe"
    f.write_bytes(FAKE_EXE)
    v = Scanner(db, use_defender=True, defender_runner=runner).scan_file(str(f), use_cache=False)
    assert v.engines["defender"].startswith(expected + ":")


def test_scanner_records_a_defender_detection(db, tmp_path, fake_mpcmdrun):
    f = tmp_path / "setup.exe"
    f.write_bytes(FAKE_EXE)
    v = Scanner(db, use_defender=True, defender_runner=runner_returning(2, THREAT_OUTPUT)).scan_file(str(f), use_cache=False)
    assert v.engines["defender"] == "detected"
    assert v.label == MALICIOUS


def test_is_active_is_asked_again_after_the_ttl(monkeypatch):
    calls: list[int] = []
    clock = [1000.0]
    monkeypatch.setattr(defender, "_active", None)
    monkeypatch.setattr(defender, "_query_active", lambda: calls.append(1) or len(calls) % 2 == 1)
    monkeypatch.setattr(defender.time, "monotonic", lambda: clock[0])
    assert defender.is_active() is True
    clock[0] += defender.ACTIVE_TTL - 1
    assert defender.is_active() is True and len(calls) == 1
    clock[0] += 2
    assert defender.is_active() is False and len(calls) == 2
    assert defender.is_active(refresh=True) is True and len(calls) == 3
