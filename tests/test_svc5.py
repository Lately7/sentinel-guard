"""Worker startup diagnostics and stderr isolation."""

from __future__ import annotations

import ctypes
import logging
import os
import time
from types import SimpleNamespace

import pytest

from sentinel.gate_v2.contract import StageStatus
from sentinel.service import worker, workerclient
from sentinel.service.workerclient import WorkerFailure, WorkerSession

pytestmark = pytest.mark.skipif(os.name != "nt", reason="restricted workers need Windows")


def _call(session: WorkerSession) -> dict:
    return session.call("scan", {}, deadline_ns=time.monotonic_ns() + 5_000_000_000)


def test_stderr_is_separate_drained_and_bounded() -> None:
    process = worker.launch(["-c", "import sys; sys.stderr.write('x' * 131072 + 'Fail'); "
                             "sys.stderr.flush(); print('ready')"])
    try:
        assert process.stdout.read(4096) == b"ready\r\n"
        assert process.wait(5) == 0
    finally:
        process.kill()
    assert process.stderr_tail() == "x" * 2044 + "Fail"


def test_failed_start_logs_stderr_but_status_keeps_only_exit_code(monkeypatch, caplog) -> None:
    monkeypatch.setattr(workerclient.worker_mod, "bootstrap", lambda module: [
        "-c", "import sys; sys.stderr.write('startup marker\\n'); sys.exit(3)"])
    session = WorkerSession()
    with caplog.at_level(logging.WARNING), pytest.raises(WorkerFailure) as caught:
        _call(session)
    assert caught.value.code == "WORKER_UNAVAILABLE"
    assert session.last_failure == "exit 0x3"
    assert "startup marker" in caplog.text
    assert "startup marker" not in session.last_failure


def test_stderr_is_not_logged_after_a_successful_start(monkeypatch, caplog) -> None:
    session = WorkerSession()
    secret = "private parse content"
    process = SimpleNamespace(wait=lambda timeout: None, kill=lambda: None,
                              stderr_tail=lambda: secret)
    monkeypatch.setattr(session, "_start", lambda deadline_ns: setattr(session, "_proc", process))

    def fail_scan(*args, **kwargs) -> dict:
        raise WorkerFailure(StageStatus.ERROR, "PARSE_FAILED")

    monkeypatch.setattr(session, "_send", fail_scan)
    with caplog.at_level(logging.WARNING), pytest.raises(WorkerFailure) as caught:
        _call(session)
    assert caught.value.code == "PARSE_FAILED"
    assert secret not in caplog.text
    session.close()


@pytest.mark.parametrize(("failure", "expected"), [
    (WorkerFailure(StageStatus.ERROR, "INIT_REFUSED"), "INIT_REFUSED"),
    (WorkerFailure(StageStatus.TIMEOUT, "WORKER_TIMEOUT"), "WORKER_TIMEOUT"),
    (WorkerFailure(StageStatus.ERROR, "WORKER_DIED"), "WORKER_DIED"),
    (OSError(1314, "CreateProcessAsUser failed (Windows error 1314)"), "Windows error 1314"),
])
def test_start_failure_replaces_stale_status(monkeypatch, failure, expected) -> None:
    session = WorkerSession()
    session.last_failure = "exit 0x99"

    def fail_start(deadline_ns: int) -> None:
        raise failure

    monkeypatch.setattr(session, "_start", fail_start)
    with pytest.raises(WorkerFailure) as caught:
        _call(session)
    assert caught.value.code == "WORKER_UNAVAILABLE"
    assert expected in session.last_failure
    assert "exit 0x99" not in session.last_failure


def test_unexpected_start_exception_is_recorded_and_typed(monkeypatch, caplog) -> None:
    session = WorkerSession()

    def fail_start(deadline_ns: int) -> None:
        raise ctypes.ArgumentError("bad startup argument")

    monkeypatch.setattr(session, "_start", fail_start)
    with caplog.at_level(logging.WARNING), pytest.raises(WorkerFailure) as caught:
        _call(session)
    assert caught.value.code == "WORKER_UNAVAILABLE"
    assert "ArgumentError" in session.last_failure
    assert "bad startup argument" in session.last_failure
    assert session.last_failure in caplog.text
