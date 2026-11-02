"""`sentinel scan` exit codes: malicious 2 > could not check 3 > suspicious 1 > clean 0 (RT-011)."""

from __future__ import annotations

import subprocess

from conftest import MARKER
from sentinel.__main__ import main
from sentinel.engine import defender
from sentinel.gate_v2 import defender as gate_defender

# Harmless files: a PE header behind a document name is "suspicious" by name
# alone; the test marker is "malicious" through the test-only rule pack.
DISGUISED = ("invoice.pdf.exe", b"MZ" + b"\0" * 510)
CLEAN = ("notes.txt", b"just text\n")


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def scan(*paths: str) -> int:
    return main(["scan", "--no-clamav", "--no-defender", *paths])


def test_clean_is_zero(tmp_path):
    assert scan(write(tmp_path, *CLEAN)) == 0


def test_suspicious_is_one(tmp_path):
    assert scan(write(tmp_path, *DISGUISED)) == 1


def test_suspicious_plus_unreadable_is_three(tmp_path):
    assert scan(write(tmp_path, *DISGUISED), str(tmp_path / "missing.bin")) == 3


def test_malicious_wins_over_unreadable(tmp_path, marker_rule):
    bad = write(tmp_path, "payload.bin", b"\0" + MARKER)
    assert scan(bad, str(tmp_path / "missing.bin")) == 2


def test_engine_failure_is_three_even_when_suspicious(tmp_path, monkeypatch):
    def timed_out(argv, deadline_ns, cancel):
        raise subprocess.TimeoutExpired(argv, 0)

    monkeypatch.setattr(defender, "mpcmdrun_path", lambda: r"C:\fake\MpCmdRun.exe")
    monkeypatch.setattr(defender, "available", lambda: True)
    monkeypatch.setattr(gate_defender, "_run", timed_out)
    f = write(tmp_path, *DISGUISED)
    assert main(["scan", "--no-clamav", f]) == 3


def test_a_file_not_fully_checked_is_three(tmp_path, monkeypatch):
    # A required engine that did not finish leaves "unknown": neither 0 nor 1.
    def fails(argv, deadline_ns, cancel):
        raise subprocess.TimeoutExpired(argv, 0)

    monkeypatch.setattr(defender, "mpcmdrun_path", lambda: r"C:\fake\MpCmdRun.exe")
    monkeypatch.setattr(defender, "available", lambda: True)
    monkeypatch.setattr(gate_defender, "_run", fails)
    assert main(["scan", "--no-clamav", write(tmp_path, "setup.exe", b"MZ" + b"\0" * 510)]) == 3

