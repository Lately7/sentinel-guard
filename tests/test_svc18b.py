"""Regressions for the phased ETW check review."""

import json
import logging
import os
import queue
import threading

from sentinel.service import etw
from test_svc17 import process_payload


def start_event(pid: int, phase: str, *, parent: int | None = None) -> etw.RawEvent:
    return etw.RawEvent(etw.PROCESS_CLASS, 1, 4, 0, 0, 1,
                        process_payload(pid, parent=os.getpid() if parent is None else parent),
                        phase=phase)


def deliver(observer: etw.EtwObserver, raw: etw.RawEvent) -> None:
    parsed = etw.parse_event(raw)
    observer._check_raw_event(raw, parsed)
    if parsed is not None:
        observer._parsed(parsed)


class Child:
    def __init__(self, pid: int) -> None:
        self.pid = pid

    def __enter__(self) -> "Child":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class CheckCollector:
    def __init__(self, observer: etw.EtwObserver, on_end=None) -> None:
        self.observer = observer
        self.phase = "W"
        self.flush_every = 0.0
        self.queue: queue.Queue[object] = queue.Queue()
        self.priority_queue: queue.Queue[object] = queue.Queue()
        self.on_end = on_end

    def set_phase(self, phase: str) -> bool:
        if self.phase == "S":
            return False
        self.phase = phase
        if phase == "E" and self.on_end:
            self.on_end()
        return True

    def measured(self) -> dict[str, dict[str, int]]:
        return {}

    def session_stats(self) -> dict[str, int]:
        return {}

    def flush(self) -> int:
        return 0


def clock_check(monkeypatch, observer: etw.EtwObserver, popen, on_end=None):
    now = [0.0]
    monkeypatch.setattr(etw.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(etw.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    monkeypatch.setattr(etw.subprocess, "Popen", popen)
    collector = CheckCollector(observer, on_end)
    observer.collector = collector
    observer.state = "checking"
    return collector


def test_second_collector_stop_waits_for_first_backend_stop() -> None:
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()

    class Backend:
        def stop(self) -> None:
            entered.set()
            assert release.wait(1)

    collector = etw.Collector(Backend(), lambda _event: None)
    first = threading.Thread(target=collector.stop)
    second = threading.Thread(target=lambda: (collector.stop(), returned.set()))
    first.start()
    assert entered.wait(1)
    second.start()
    assert not returned.wait(0.05)
    release.set()
    first.join(1)
    second.join(1)
    assert not first.is_alive() and not second.is_alive() and returned.is_set()


def test_callback_phase_is_used_after_phase_changes() -> None:
    collector = etw.Collector(None, lambda _event: None)
    collector.set_phase("W")
    collector.callback(start_event(101, "F"))
    collector.set_phase("F")
    queued = collector.queue.get_nowait()
    assert queued.phase == "W"
    assert collector.measured()["W"]["p1"] == 1
    observer = etw.EtwObserver(lambda _path: None)
    observer.state = "checking"
    deliver(observer, queued)
    assert observer._check_event_phases[101] == "W"


def test_earliest_child_phase_wins_and_late_start_cannot_pass(monkeypatch) -> None:
    observer = etw.EtwObserver(lambda _path: None)
    spawned = []

    def popen(*_args, **_kwargs):
        pid = 101 + len(spawned)
        spawned.append(pid)
        if len(spawned) == 2:
            deliver(observer, start_event(pid, "F"))
            deliver(observer, start_event(spawned[0], "W"))
        return Child(pid)

    collector = clock_check(monkeypatch, observer, popen)
    assert observer._check_schema(collector) == ""
    assert observer._pass_phase == "W"
    assert not observer.flush_assist

    observer2 = etw.EtwObserver(lambda _path: None)
    children = []

    def late_popen(*_args, **_kwargs):
        pid = 201 + len(children)
        children.append(pid)
        return Child(pid)

    collector2 = clock_check(monkeypatch, observer2, late_popen,
                             lambda: deliver(observer2, start_event(children[0], "E")))
    assert observer2._check_schema(collector2) == "no_start_events"
    assert observer2._pass_phase is None
    assert observer2._late_children == ["A"]


def test_final_rescan_accepts_queued_window_start_and_parsed_start_is_not_mismatch(monkeypatch) -> None:
    observer = etw.EtwObserver(lambda _path: None)
    children = []

    def popen(*_args, **_kwargs):
        pid = 301 + len(children)
        children.append(pid)
        return Child(pid)

    collector = clock_check(monkeypatch, observer, popen,
                            lambda: collector.queue.put(object()))
    def drain(_timeout):
        deliver(observer, start_event(children[0], "W"))
        collector.queue.get_nowait()
        collector.queue.task_done()
        return False
    observer._stopping.wait = drain
    assert observer._check_schema(collector) == ""
    assert observer._pass_phase == "W"

    observer2 = etw.EtwObserver(lambda _path: None)
    children.clear()
    collector2 = clock_check(monkeypatch, observer2, popen,
                             lambda: deliver(observer2, start_event(children[0], "E")))
    assert observer2._check_schema(collector2) == "no_start_events"


def test_mismatch_tracks_parsing_per_raw_start() -> None:
    observer = etw.EtwObserver(lambda _path: None)
    observer.state = "checking"
    good = start_event(601, "F")
    bad = start_event(602, "F", parent=os.getpid() + 1)
    deliver(observer, good)
    deliver(observer, bad)
    assert 601 in observer._raw_start_pids and 601 not in observer._raw_start_mismatch_pids
    assert 602 in observer._raw_start_mismatch_pids


def test_stop_phase_is_terminal_and_b_is_not_spawned_after_stop(monkeypatch) -> None:
    collector = etw.Collector(None, lambda _event: None)
    collector.set_phase("W")
    collector.stop_phase()
    assert not collector.set_phase("B") and collector.phase == "S"

    observer = etw.EtwObserver(lambda _path: None)
    spawned = []

    def popen(*_args, **_kwargs):
        spawned.append(1)
        return Child(400)

    check_collector = clock_check(monkeypatch, observer, popen)
    def phase_end(_collector, phase):
        if phase == "W":
            observer._stopping.set()
    observer._phase_end = phase_end
    assert observer._check_schema(check_collector) == "no_start_events"
    assert len(spawned) == 1


def test_pass_does_not_reopen_after_stop_during_lock_acquisition() -> None:
    observer = etw.EtwObserver(lambda _path: None, check=lambda _collector: "")

    class Backend:
        def start(self, _callback):
            return etw.StartResult("STARTED")

        def process(self):
            return None

        def stop(self):
            return None

        def loss(self):
            return 0, 0, 0

    observer.backend_factory = lambda _guid: Backend()
    original_log = observer._log_result
    original_lock = observer._lock

    class StopOnAcquire:
        def __enter__(self):
            observer._stopping.set()
            return original_lock.__enter__()

        def __exit__(self, *args):
            return original_lock.__exit__(*args)

    def inject_stop(collector, reason):
        original_log(collector, reason)
        observer._lock = StopOnAcquire()

    observer._log_result = inject_stop
    observer.start()
    assert observer.state != "on"


def test_sleep_gauge_separates_sleep_from_overrun_and_resets(caplog, monkeypatch) -> None:
    observer = etw.EtwObserver(lambda _path: None)
    now = [1.0]
    monkeypatch.setattr(etw.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(etw.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    observer._check_sleep(0.5)
    collector = CheckCollector(observer)
    with caplog.at_level(logging.WARNING):
        observer._phase_end(collector, "W")
        observer._phase_end(collector, "B")
    rows = [json.loads(row.message.split("phase ", 1)[1][2:]) for row in caplog.records
            if row.message.startswith("etw check: phase ")]
    assert rows[0]["overrun_ms"] == 500 and rows[0]["worst_ms"] == 0
    assert rows[1]["overrun_ms"] == 0 and rows[1]["sleeps"] == 0


def test_b_spawn_failure_is_recorded_once_and_schedule_continues(monkeypatch) -> None:
    observer = etw.EtwObserver(lambda _path: None)
    calls = []

    def popen(*_args, **_kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise OSError(5, "denied")
        return Child(501)

    collector = clock_check(monkeypatch, observer, popen)
    assert observer._check_schema(collector) == "no_start_events"
    assert len(calls) == 2 and observer.spawn_errors == {"B": 5}
    assert collector.phase == "E"


def test_a_spawn_failure_still_propagates(monkeypatch) -> None:
    observer = etw.EtwObserver(lambda _path: None)

    def popen(*_args, **_kwargs):
        raise OSError(5, "denied")

    collector = clock_check(monkeypatch, observer, popen)
    try:
        observer._check_schema(collector)
    except OSError as error:
        assert error.errno == 5
    else:
        assert False, "A spawn failure must reach the caller"


def test_result_lists_callback_phase_late_child_and_spawn_error(caplog) -> None:
    observer = etw.EtwObserver(lambda _path: None)
    collector = etw.Collector(None, lambda _event: None)
    observer._check_children[701] = 0.0
    observer._check_event_phases[701] = "E"
    observer._late_children = ["A"]
    observer.spawn_errors["B"] = 5
    with caplog.at_level(logging.WARNING):
        observer._log_result(collector, "no_start_events")
    row = next(row for row in caplog.records if row.message.startswith("etw check: result "))
    fields = json.loads(row.message.removeprefix("etw check: result "))
    assert fields["children"]["A"][0] == "E"
    assert fields["late"] == ["A"] and fields["spawn_errors"] == {"B": 5}


def test_stop_line_is_logged_once_after_failed_state_change(caplog) -> None:
    observer = etw.EtwObserver(lambda _path: None)

    class Backend:
        final_stats = None

        def stop(self):
            return None

    collector = etw.Collector(Backend(), lambda _event: None)
    collector.set_phase("W")
    observer.collector = collector
    observer.state = "no_start_events"
    with caplog.at_level(logging.WARNING):
        observer.stop()
        observer.stop()
    assert sum(row.message.startswith("etw check: stop ") for row in caplog.records) == 1


def test_service_stop_waits_for_the_check_stop_line(caplog) -> None:
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()
    observer = etw.EtwObserver(lambda _path: None)

    class Backend:
        final_stats = None

        def stop(self):
            entered.set()
            assert release.wait(1)

    collector = etw.Collector(Backend(), lambda _event: None)
    collector.set_phase("W")
    observer.collector = collector
    observer.state = "no_start_events"
    first = threading.Thread(target=observer._stop_check, args=(collector,))
    second = threading.Thread(target=lambda: (observer.stop(), returned.set()))
    with caplog.at_level(logging.WARNING):
        first.start()
        assert entered.wait(1)
        second.start()
        assert not returned.wait(0.05)
        release.set()
        first.join(1)
        second.join(1)
    assert not first.is_alive() and not second.is_alive()
    assert returned.is_set()
    assert sum(row.message.startswith("etw check: stop ") for row in caplog.records) == 1


# Review fixes (Claude).


def test_sleep_gauge_records_oversleep_not_the_sleep_itself(monkeypatch) -> None:
    observer = etw.EtwObserver(lambda _path: None)
    now, perf = [1.0], [10.0]
    monkeypatch.setattr(etw.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(etw.time, "perf_counter", lambda: perf[0])

    def sleep(seconds):
        now[0] += seconds + 0.2
        perf[0] += seconds + 0.2

    monkeypatch.setattr(etw.time, "sleep", sleep)
    observer._check_sleep(now[0] + 0.05)
    assert 199 <= observer._sleep_worst_ms <= 201


def test_service_stop_waits_at_most_a_second_for_another_threads_stop_line(monkeypatch) -> None:
    observer = etw.EtwObserver(lambda _path: None)

    class Lost:
        phase = "F"

        def stop_phase(self):
            self.phase = "S"

        def stop(self):
            return False

    observer.collector = Lost()
    waits = []
    monkeypatch.setattr(observer._stop_line_done, "wait", lambda timeout: waits.append(timeout) or False)
    observer.stop()
    assert waits == [etw.STOP_LINE_WAIT] and etw.STOP_LINE_WAIT <= 1.0


def test_result_line_carries_the_late_phase_tallies(caplog) -> None:
    observer = etw.EtwObserver(lambda _path: None)
    collector = etw.Collector(None, lambda _event: None)
    collector.set_phase("E")
    collector.callback(etw.RawEvent(etw.PROCESS_CLASS, 2, 4, 0, 0, 1, bytes(16)))
    with caplog.at_level(logging.WARNING):
        observer._log_result(collector, "no_start_events")
    rows = [json.loads(row.message.split("result ", 1)[1]) for row in caplog.records
            if row.message.startswith("etw check: result ")]
    assert rows and rows[0]["phase_e"]["p2"] == 1
