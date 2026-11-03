"""Regressions for service shutdown, worker catch-up, and repair reporting."""

from __future__ import annotations

import ctypes
import os
import threading
from collections import OrderedDict
from types import SimpleNamespace

import pytest

from sentinel.gate_v2.scope import SourceEntry
from sentinel.service import repair
from sentinel.service.backend import ProductBackend, _Job


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows service")


def test_stop_cancels_both_running_lanes_before_worker_close() -> None:
    backend = object.__new__(ProductBackend)
    backend._stop = threading.Event()
    backend.observers = None
    backend._lock = threading.Lock()
    asked = _Job("asked", "C:/asked", "on_demand", None, "", None)
    observed = _Job("observed", "C:/observed", "journal", None, "", None)
    backend._jobs = OrderedDict(((asked.job_id, asked),))
    events: list[str] = []

    def lane(job: _Job) -> SimpleNamespace:
        return SimpleNamespace(_lock=threading.Lock(), running={object(): [job, 0.0, False]},
                               stop=lambda: events.append("lane stopped"))

    backend._asked_lane = lane(asked)
    backend._observed_lane = lane(observed)
    backend.barrier = SimpleNamespace(revoke=lambda timeout: events.append("barrier closed") or True)

    def close() -> None:
        assert asked.cancel.cancelled() and observed.cancel.cancelled()
        assert events[0] == "barrier closed"
        events.append("worker closed")

    backend.scanner = SimpleNamespace(isolation=SimpleNamespace(close=close))
    assert backend.stop(0.1)
    assert events[-1] == "worker closed"


def test_watch_owes_one_reconciliation_after_each_failure_spell() -> None:
    backend = object.__new__(ProductBackend)
    backend._stop = SimpleNamespace(wait=lambda delay: False)
    backend._lock = threading.Lock()
    backend._worker_down_skipped = 0
    backend._worker_down_owed = False
    backend._asked_lane = SimpleNamespace(sweep=lambda: None)
    backend._observed_lane = SimpleNamespace(sweep=lambda: None)
    backend._retry_due = lambda: None
    failure = ["INSTALL_INTEGRITY"]
    backend.scanner = SimpleNamespace(isolation=SimpleNamespace(failure=lambda: failure[0]))
    owed: list[int] = []
    backend.observers = SimpleNamespace(owe=lambda: owed.append(1))
    job = _Job("observed", "C:/ordinary", "journal", None, "", None)

    def tick() -> None:
        waits = iter((False, True))
        backend._stop = SimpleNamespace(wait=lambda delay: next(waits))
        backend._watch()

    backend._after_observed(job)
    tick()
    assert owed == []
    failure[0] = ""
    tick()
    tick()
    assert owed == [1] and backend._worker_down_skipped == 1
    failure[0] = "WORKER_UNAVAILABLE"
    backend._after_observed(job)
    failure[0] = ""
    observer = backend.observers
    backend.observers = None
    tick()
    assert owed == [1] and backend._worker_down_owed
    backend.observers = observer
    tick()
    assert owed == [1, 1] and backend._worker_down_skipped == 2


def test_open_process_access_denied_refuses_repair(monkeypatch: pytest.MonkeyPatch) -> None:
    process = repair.Process(12345, 1, "C:/ordinary")
    monkeypatch.setattr(repair, "_k32", SimpleNamespace(OpenProcess=lambda *args: 0))
    monkeypatch.setattr(ctypes, "get_last_error", lambda: repair.ERROR_ACCESS_DENIED)
    with pytest.raises(repair.RepairError) as error:
        repair.stop_process(process)
    assert error.value.code == "REFUSED_PROCESS"
    monkeypatch.setattr(ctypes, "get_last_error", lambda: repair.ERROR_INVALID_PARAMETER)
    assert repair.stop_process(process) is False


def test_denied_process_never_reaches_quarantine(monkeypatch: pytest.MonkeyPatch) -> None:
    path = "C:/ordinary"
    monkeypatch.setattr(repair.identity, "measure", lambda *args, **kwargs: SimpleNamespace(
        ok=True, identity=SimpleNamespace(sha256="a" * 64)))
    monkeypatch.setattr(repair, "_same_file", lambda a, b: a == b)
    monkeypatch.setattr(repair, "stop_process", lambda p: (_ for _ in ()).throw(
        repair.RepairError("REFUSED_PROCESS")))
    monkeypatch.setattr(repair.quarantine, "quarantine", lambda *args, **kwargs: pytest.fail("quarantine"))
    proposal = repair.Repair("r", path, "a" * 64, (repair.Process(12345, 1, path),), ())
    with pytest.raises(repair.RepairError) as error:
        repair.execute(SimpleNamespace(), proposal, {})
    assert error.value.code == "REFUSED_PROCESS"


def test_repair_plan_and_result_name_persistence_left_in_place(monkeypatch: pytest.MonkeyPatch) -> None:
    path = "C:/ordinary"
    monkeypatch.setattr(repair.winfile, "is_protected", lambda p: False)
    monkeypatch.setattr(repair, "find_processes", lambda *args, **kwargs: ())
    run_value = repair.RunValue("HKLM", "Run", 256, "OldRun", path, 1)
    monkeypatch.setattr(repair, "find_autostart", lambda *args, **kwargs: (run_value,))
    monkeypatch.setattr(repair, "_same_file", lambda a, b: a == b)
    tasks = lambda: (SourceEntry("task", "OldTask", path), SourceEntry("task", "OtherTask", "C:/other"))
    wmi = lambda: (SourceEntry("wmi", "OldConsumer", path),)
    proposal = repair.plan(path, "a" * 64, tasks=tasks, wmi=wmi)
    summary = repair.describe(proposal)
    assert "OldTask" in summary and "OldConsumer" in summary
    assert "để nguyên" in summary
    assert proposal.tasks == ("OldTask",) and proposal.wmi_consumers == ("OldConsumer",)

    monkeypatch.setattr(repair.identity, "measure", lambda *args, **kwargs: SimpleNamespace(
        ok=True, identity=SimpleNamespace(sha256="a" * 64)))
    monkeypatch.setattr(repair, "_release", lambda p: None)
    monkeypatch.setattr(repair.quarantine, "quarantine", lambda *args, **kwargs: "q1")
    reg = SimpleNamespace(HKEY_LOCAL_MACHINE="HKLM", KEY_READ=1, KEY_SET_VALUE=2,
                          OpenKey=lambda *args: (_ for _ in ()).throw(FileNotFoundError()))
    result = repair.execute(SimpleNamespace(), proposal, {}, reg=reg)
    assert result["autostart_left"] == 1
    assert result["left_in_place"] == ["Để nguyên tác vụ: OldTask", "Để nguyên bộ tiếp nhận WMI: OldConsumer",
                                       "Chưa gỡ giá trị Run: OldRun"]


def test_a_listing_that_fails_does_not_cost_the_repair(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(repair.winfile, "is_protected", lambda p: False)
    monkeypatch.setattr(repair, "find_processes", lambda *args, **kwargs: ())
    monkeypatch.setattr(repair, "find_autostart", lambda *args, **kwargs: ())

    def broken():
        raise OSError("task scheduler unavailable")

    proposal = repair.plan("C:/ordinary", "a" * 64, tasks=broken, wmi=broken)
    assert proposal.tasks == () and proposal.wmi_consumers == ()
