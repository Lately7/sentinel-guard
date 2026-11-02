"""freshclam: only exit 0 means "up to date or updated" (RT-029)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sentinel.engine import clamav


@pytest.fixture
def fake_freshclam(monkeypatch, tmp_path):
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, run.code, stdout=run.out, stderr="")

    run.code, run.out = 0, "daily.cvd database is up-to-date\n"
    monkeypatch.setattr(clamav, "install_dir", lambda: Path(tmp_path))
    monkeypatch.setattr(clamav, "has_database", lambda: True)  # an older database is already there
    monkeypatch.setattr(clamav.subprocess, "run", run)
    monkeypatch.setattr(clamav.Clamd, "command", lambda self, cmd, timeout=10: b"RELOADING")
    return run


def test_exit_zero_is_ok(fake_freshclam):
    assert clamav.update() == "ok"


@pytest.mark.parametrize("code", [1, 2, 40, 55, 62])
def test_any_other_exit_is_an_error_even_with_an_old_database(fake_freshclam, code):
    fake_freshclam.code, fake_freshclam.out = code, "ERROR: Can't connect to database.clamav.net\n"
    res = clamav.update()
    assert res.startswith(f"error: freshclam exit {code}")
