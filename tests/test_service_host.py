"""A1: service shell state logic with a fake SCM (R13b P1). Installing and
starting the real service is the owner's elevated acceptance step."""

from __future__ import annotations

import threading

from sentinel.service import host as h


class FakeScm:
    def __init__(self) -> None:
        self.reports: list[tuple[int, int, int, int]] = []  # state, accepted, exit, checkpoint
        self.service_code = 0

    def set_status(self, state, *, accepted, exit_code, checkpoint, wait_hint_ms, service_code=0):
        self.reports.append((state, accepted, exit_code, checkpoint))
        self.service_code = service_code


class FakeService:
    def __init__(self, *, fail_start=False, barrier_closes=True, closes_on_call=1) -> None:
        self.fail_start, self.barrier_closes, self.closes_on_call = fail_start, barrier_closes, closes_on_call
        self.started = threading.Event()
        self.stopped_with: float | None = None
        self.stop_calls = 0

    def start(self):
        if self.fail_start:
            raise RuntimeError("cannot open the pipe")
        self.started.set()

    def stop(self, timeout):
        self.stopped_with = timeout
        self.stop_calls += 1
        return self.barrier_closes and self.stop_calls >= self.closes_on_call


def run_until_stop(host: h.ServiceHost, control: int) -> None:
    t = threading.Thread(target=host.run)
    t.start()
    assert host.service.started.wait(5)
    for _ in range(100):  # until RUNNING has been reported
        if host.state == h.SERVICE_RUNNING:
            break
        threading.Event().wait(0.01)
    assert host.control(control) == h.NO_ERROR
    t.join(5)
    assert not t.is_alive()


def test_start_run_stop_sequence_and_stopped_only_after_the_barrier():
    scm, svc = FakeScm(), FakeService()
    host = h.ServiceHost(svc, scm)
    run_until_stop(host, h.SERVICE_CONTROL_STOP)
    states = [r[0] for r in scm.reports]
    assert states == [h.SERVICE_START_PENDING, h.SERVICE_RUNNING, h.SERVICE_STOP_PENDING, h.SERVICE_STOPPED]
    assert 0 < svc.stopped_with <= h.STOP_BARRIER_SECONDS and host.barrier_closed is True
    running = scm.reports[1]
    assert running[1] == h.SERVICE_ACCEPT_STOP | h.SERVICE_ACCEPT_PRESHUTDOWN
    assert scm.reports[0][3] > 0 and scm.reports[2][3] > 0, "pending states carry a checkpoint"
    assert scm.reports[-1][3] == 0 and scm.reports[-1][2] == h.NO_ERROR


def test_preshutdown_stops_the_same_way():
    scm, svc = FakeScm(), FakeService()
    run_until_stop(h.ServiceHost(svc, scm), h.SERVICE_CONTROL_PRESHUTDOWN)
    assert [r[0] for r in scm.reports][-2:] == [h.SERVICE_STOP_PENDING, h.SERVICE_STOPPED]
    assert svc.stopped_with is not None


def test_failed_start_reports_stopped_with_an_error():
    scm = FakeScm()
    host = h.ServiceHost(FakeService(fail_start=True), scm)
    host.run()
    assert scm.reports[-1][0] == h.SERVICE_STOPPED and scm.reports[-1][2] == h.ERROR_SERVICE_SPECIFIC_ERROR
    assert scm.service_code == h.EXIT_START_FAILED


def test_stopped_waits_for_a_slow_barrier_with_advancing_checkpoints():
    # R15-4 / R11 invariant 11: "off" is published only after the action boundary
    # closed. SCM treats a checkpoint that stops advancing as a hung service.
    scm, svc = FakeScm(), FakeService(closes_on_call=3)
    host = h.ServiceHost(svc, scm)
    run_until_stop(host, h.SERVICE_CONTROL_STOP)
    assert svc.stop_calls == 3 and host.barrier_closed is True
    pending = [r for r in scm.reports if r[0] == h.SERVICE_STOP_PENDING]
    assert len(pending) == 3
    assert [r[3] for r in pending] == sorted({r[3] for r in pending})
    assert scm.reports[-1][0] == h.SERVICE_STOPPED and scm.reports[-1][2] == h.NO_ERROR


def test_a_barrier_that_never_closes_is_not_a_clean_stop(monkeypatch):
    monkeypatch.setattr(h, "STOP_BARRIER_SECONDS", 0.05)
    monkeypatch.setattr(h, "STOP_SLICE_SECONDS", 0.01)
    scm, svc = FakeScm(), FakeService(barrier_closes=False)
    host = h.ServiceHost(svc, scm)
    run_until_stop(host, h.SERVICE_CONTROL_STOP)
    assert host.barrier_closed is False and svc.stop_calls > 1
    assert scm.reports[-1][0] == h.SERVICE_STOPPED
    assert scm.reports[-1][2] == h.ERROR_SERVICE_SPECIFIC_ERROR and scm.service_code == h.EXIT_BARRIER_OPEN


def test_stop_before_running_is_ignored_and_unknown_controls_are_refused():
    scm = FakeScm()
    host = h.ServiceHost(FakeService(), scm)
    assert host.control(h.SERVICE_CONTROL_STOP) == h.NO_ERROR
    assert scm.reports == [], "nothing to stop yet; start-up is not interrupted"
    assert host.control(0x80) == h.ERROR_CALL_NOT_IMPLEMENTED
    assert host.control(h.SERVICE_CONTROL_INTERROGATE) == h.NO_ERROR
