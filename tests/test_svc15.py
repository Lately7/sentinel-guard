"""Bounded interpreter diagnosis after an installed worker fails to start."""

from __future__ import annotations

import ast
import ctypes
import json
import logging
import os
from pathlib import Path

import pytest

from sentinel.gate_v2.contract import StageStatus
from sentinel.service import worker, workerclient
from sentinel.service.workerclient import WorkerFailure, WorkerSession

pytestmark = pytest.mark.skipif(os.name != "nt", reason="restricted workers need Windows")
FAKE_SERVICE_SID = "S-1-5-80-1111111111-2222222222-3333333333-4000000000-1234567890"


class Probe:
    def __init__(self, code: int | None = 0, stderr: str = "") -> None:
        self.code, self.stderr = code, stderr
        self.killed = False
        self.waited: list[int] = []

    def wait(self, timeout: int) -> int | None:
        self.waited.append(timeout)
        return self.code

    def kill(self) -> None:
        self.killed = True

    def stderr_tail(self) -> str:
        return self.stderr


def test_token_context_and_dacl_variant_use_only_disposable_token() -> None:
    context = worker._diagnostic_context(FAKE_SERVICE_SID)
    assert context["variant"] == "context"
    assert context["user"] and context["groups"] and context["session"].isdigit()
    assert context["station"] and context["desktop"] and context["executable"]
    assert "privileges" in context
    token = worker._restricted_low_token(FAKE_SERVICE_SID, grant_dacl=True)
    worker._k32.CloseHandle(token)


def test_diagnosis_uses_only_bounded_interpreter_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker, "_diagnostic_context", lambda sid: {"variant": "context"})
    calls: list[tuple[list[str], dict, Probe]] = []

    def launch(args: list[str], **options: object) -> Probe:
        probe = Probe()
        calls.append((args, options, probe))
        return probe

    monkeypatch.setattr(worker, "launch", launch)
    results = worker.diagnose("python.exe", "version", "S-1-5-80-1")
    expected = [({}, "real"), ({"private_desktop": False}, "service_desktop"),
                ({"restricting": False}, "no_restricting_sids"),
                ({"low_integrity": False}, "parent_integrity"),
                ({"no_window": True}, "create_no_window"),
                ({"grant_dacl": True}, "grant_restricting_dacl"),
                ({"job_limits": False}, "job_kill_only")]
    assert len(calls) == 14
    for index, (overrides, variant) in enumerate(expected):
        for step, code in enumerate(("pass", "import ctypes")):
            args, options, probe = calls[index * 2 + step]
            assert args == ["-c", code]
            assert options == {"python": "python.exe", "cwd": "version", "service_sid": "S-1-5-80-1",
                               **overrides}
            assert probe.waited == [5] and probe.killed
            assert results[index * 2 + step + 1]["variant"] == variant
    assert results[-1] == {"variant": "summary", "ctypes_passed": "7", "variants": "7"}


def test_failed_probe_records_api_error_or_exit_and_skips_second_step(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker, "_diagnostic_context", lambda sid: {"variant": "context"})
    attempts = 0
    processes: list[Probe] = []

    def launch(args: list[str], **options: object) -> Probe:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise worker.WorkerError(1314, "CreateProcessAsUser failed (Windows error 1314)")
        probe = Probe(3 if attempts == 2 else 0, "x" * 3000)
        processes.append(probe)
        return probe

    monkeypatch.setattr(worker, "launch", launch)
    results = worker.diagnose("python.exe", "version", "S-1-5-80-1")
    assert results[1] == {"variant": "real", "step": "pass", "call": "CreateProcessAsUser",
                          "windows_error": "1314", "stderr": ""}
    assert results[2]["variant"] == "service_desktop" and results[2]["exit_code"] == "0x3"
    assert len(results[2]["stderr"]) == 2048
    assert attempts == 12  # two failed first steps, then five complete variants
    assert all(p.killed for p in processes)


def test_timed_out_probe_closes_its_job_and_context_failure_does_not_hide_variants(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker, "_diagnostic_context", lambda sid: (_ for _ in ()).throw(OSError(5, "denied")))
    probes: list[Probe] = []

    def launch(args: list[str], **options: object) -> Probe:
        probe = Probe(None if not probes else 0)
        probes.append(probe)
        return probe

    monkeypatch.setattr(worker, "launch", launch)
    results = worker.diagnose("python.exe", "version", "S-1-5-80-1")
    assert results[0]["variant"] == "context" and results[0]["windows_error"] == "5"
    assert results[1]["exit_code"] == "timeout"
    assert probes[0].waited == [5] and probes[0].killed
    assert results[-1]["variant"] == "summary"


def test_both_diagnostic_job_modes_keep_kill_on_close(monkeypatch: pytest.MonkeyPatch) -> None:
    flags: list[int] = []
    monkeypatch.setattr(worker._k32, "CreateJobObjectW", lambda sa, name: 123)

    def set_info(job: int, kind: int, pointer: object, size: int) -> bool:
        info = ctypes.cast(pointer, ctypes.POINTER(worker.JOBOBJECT_EXTENDED_LIMIT_INFORMATION)).contents
        flags.append(info.BasicLimitInformation.LimitFlags)
        return True

    monkeypatch.setattr(worker._k32, "SetInformationJobObject", set_info)
    for limits in (True, False):
        assert worker._job(512 * 1024 * 1024, limits=limits) == 123
    assert all(flag & worker.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE for flag in flags)
    assert flags[0] & worker.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    assert flags[1] == worker.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE


def test_weak_launch_options_are_selected_only_by_diagnose() -> None:
    weaker = {"private_desktop", "restricting", "low_integrity", "no_window", "grant_dacl", "job_limits"}
    for path in Path(worker.__file__).parent.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in (n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            for call in (n for n in ast.walk(function) if isinstance(n, ast.Call)):
                name = call.func.id if isinstance(call.func, ast.Name) else (
                    call.func.attr if isinstance(call.func, ast.Attribute) else "")
                if name == "launch" and ({keyword.arg for keyword in call.keywords} & weaker or any(
                        keyword.arg is None for keyword in call.keywords)):
                    assert path == Path(worker.__file__) and function.name == "diagnose"


def test_installed_failure_schedules_one_daemon_without_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(workerclient, "_diagnosis_started", False)
    monkeypatch.setattr(workerclient, "active_version", lambda: Path("C:/SentinelGuard/versions/v1"))
    threads: list[object] = []

    class Thread:
        def __init__(self, *, target: object, daemon: bool, name: str) -> None:
            assert daemon and name == "worker-diagnosis"
            self.target = target
            threads.append(self)

        def start(self) -> None:
            pass

    monkeypatch.setattr(workerclient.threading, "Thread", Thread)
    for _ in range(2):
        session = WorkerSession()
        monkeypatch.setattr(session, "_start", lambda deadline: (_ for _ in ()).throw(OSError(5, "refused")))
        with pytest.raises(WorkerFailure) as caught:
            session._ensure_started(0)
        assert caught.value.status is StageStatus.UNAVAILABLE
    assert len(threads) == 1


def test_portable_failure_does_not_schedule_diagnosis(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(workerclient, "_diagnosis_started", False)
    monkeypatch.setattr(workerclient, "active_version", lambda: None)
    monkeypatch.setattr(workerclient.threading, "Thread", lambda **kwargs: pytest.fail("diagnosis started"))
    session = WorkerSession()
    monkeypatch.setattr(session, "_start", lambda deadline: (_ for _ in ()).throw(OSError(5, "refused")))
    with pytest.raises(WorkerFailure):
        session._ensure_started(0)


def test_diagnosis_logs_one_line_per_result_and_summary_last(monkeypatch: pytest.MonkeyPatch,
                                                              caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setattr(workerclient, "_diagnosis_started", False)
    monkeypatch.setattr(workerclient, "active_version", lambda: Path("C:/SentinelGuard/versions/v1"))
    from sentinel.service import installer

    monkeypatch.setattr(installer.WindowsScm, "service_sid", lambda self, name: "S-1-5-80-1")
    monkeypatch.setattr(workerclient.worker_mod, "diagnose", lambda *args: [
        {"variant": "context", "desktop": "Service-0\\Default"},
        {"variant": "real", "step": "pass", "stderr": "first\nsecond"},
        {"variant": "summary", "ctypes_passed": "0"},
    ])
    targets: list[object] = []

    class Thread:
        def __init__(self, *, target: object, daemon: bool, name: str) -> None:
            targets.append(target)

        def start(self) -> None:
            pass

    monkeypatch.setattr(workerclient.threading, "Thread", Thread)
    workerclient._diagnose_once()
    with caplog.at_level(logging.WARNING):
        targets[0]()
    lines = [record.message for record in caplog.records if record.message.startswith("worker diagnosis:")]
    assert len(lines) == 3 and all("\n" not in line for line in lines)
    assert json.loads(lines[-1].removeprefix("worker diagnosis: "))["variant"] == "summary"


def test_diagnosis_exception_is_one_log_line(monkeypatch: pytest.MonkeyPatch,
                                             caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setattr(workerclient, "_diagnosis_started", False)
    monkeypatch.setattr(workerclient, "active_version", lambda: Path("C:/SentinelGuard/versions/v1"))
    from sentinel.service import installer

    monkeypatch.setattr(installer.WindowsScm, "service_sid", lambda self, name: "S-1-5-80-1")
    monkeypatch.setattr(workerclient.worker_mod, "diagnose", lambda *args: (_ for _ in ()).throw(ValueError("bad")))
    targets: list[object] = []

    class Thread:
        def __init__(self, *, target: object, daemon: bool, name: str) -> None:
            targets.append(target)

        def start(self) -> None:
            pass

    monkeypatch.setattr(workerclient.threading, "Thread", Thread)
    workerclient._diagnose_once()
    with caplog.at_level(logging.WARNING):
        targets[0]()
    lines = [record.message for record in caplog.records if record.message.startswith("worker diagnosis:")]
    assert lines == ["worker diagnosis: error=ValueError windows_error=0"]
