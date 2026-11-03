"""Regressions for phased process ETW verification."""

import ctypes
import logging
import os
import queue
from dataclasses import replace

from sentinel.service import etw
from test_svc17 import process_payload


def raw(opcode: int, pid: int, *, parent: int = 0, timestamp: int = 1,
        cpu: int = 0, truncated: bool = False) -> etw.RawEvent:
    return etw.RawEvent(etw.PROCESS_CLASS, opcode, 4, 0, 0, timestamp,
                        process_payload(pid, parent=parent), truncated=truncated, cpu=cpu)


def test_native_enable_is_separate_and_process_result_is_visible() -> None:
    class Api:
        def __init__(self):
            self.enables = 0
            self.OpenTraceW = lambda *_args: 7
            self.ProcessTrace = lambda *_args: 321

        def StartTraceW(self, *_args):
            return 0

        def EnableTraceEx2(self, *_args):
            self.enables += 1
            return 0

    native = etw.NativeBackend()
    native._api = Api()
    received = []
    assert native.start(received.append).status == "STARTED"
    assert native._api.enables == 0
    assert native.enable().status == "STARTED"
    assert native._api.enables == 1
    native.process()
    assert native.process_entered is not None
    assert native.process_result is not None and native.process_result[0] == 321
    record = etw.EVENT_RECORD()
    record.BufferContext = 0x12345
    record.EventHeader.ProviderId = etw._guid(etw.PROCESS_CLASS)
    record.EventHeader.EventDescriptor.Opcode = 1
    record.EventHeader.EventDescriptor.Version = 4
    payload = ctypes.create_string_buffer(process_payload(100, parent=os.getpid()))
    record.UserData = ctypes.addressof(payload)
    record.UserDataLength = len(payload) - 1
    native._callback(ctypes.pointer(record))
    assert received[0].cpu == 0x2345


def test_control_properties_and_stats_are_sized_for_query_flush_stop() -> None:
    props = etw._control_properties()
    data = etw.EVENT_TRACE_PROPERTIES.from_buffer(props)
    assert len(props) == ctypes.sizeof(etw.EVENT_TRACE_PROPERTIES) + 4096
    assert data.LoggerNameOffset == ctypes.sizeof(etw.EVENT_TRACE_PROPERTIES)
    assert data.LogFileNameOffset == data.LoggerNameOffset + 2048
    assert ctypes.string_at(ctypes.addressof(props) + data.LoggerNameOffset,
                            len(etw.SESSION_NAME.encode("utf-16-le"))) == etw.SESSION_NAME.encode("utf-16-le")
    data.EventsLost, data.RealTimeBuffersLost, data.LogBuffersLost = 2, 3, 4
    assert (etw._stats(props)["EventsLost"], etw._stats(props)["RealTimeBuffersLost"],
            etw._stats(props)["LogBuffersLost"]) == (2, 3, 4)


def test_native_query_failure_flush_and_first_final_stats() -> None:
    class Api:
        queries = 0
        stops = 0

        def ControlTraceW(self, _handle, _name, props, code):
            if code == 0:
                self.queries += 1
                if self.queries == 1:
                    return 87
                data = etw.EVENT_TRACE_PROPERTIES.from_buffer(props)
                data.Wnode.Guid = etw._guid(native.session_guid)
                data.EventsLost = 5
            if code == 1:
                self.stops += 1
                etw.EVENT_TRACE_PROPERTIES.from_buffer(props).EventsLost = 7
            return 0

        def EnableTraceEx2(self, *_args):
            return 0

        def CloseTrace(self, *_args):
            return 0

    native = etw.NativeBackend()
    native._api = Api()
    native.owned = True
    order = []
    native.trace = ctypes.c_uint64(7)
    native.wait_consumer = lambda: order.append("wait")
    native._api.CloseTrace = lambda *_args: order.append("close")
    try:
        native.stats()
    except OSError as error:
        assert error.errno == 87
    else:
        assert False
    assert native.loss() == (5, 0, 0)
    assert native.flush() == 0
    native.stop()
    assert order == ["wait", "close"]
    assert native.final_stats is not None
    assert native.final_stats["EventsLost"] == 7
    assert native.final_stats["stop_rc"] == 0
    native.stop()
    assert native._api.stops == 1


def test_collector_measures_phases_without_payload_logging(caplog) -> None:
    collector = etw.Collector(None, lambda _event: None)
    collector.phase = "W"
    with caplog.at_level(logging.WARNING):
        collector.callback(raw(3, os.getpid(), cpu=2))
        collector.callback(raw(1, 100, parent=os.getpid(), timestamp=0, cpu=3,
                               truncated=True))
    tally = collector.measured()["W"]
    assert tally["p3"] == 1 and tally["own_p3"] == 1 and tally["p3@2"] == 1
    assert tally["p1"] == 1 and tally["child_p1"] == 1 and tally["p1@3"] == 1
    assert tally["trunc_p1"] == 1 and tally["ts_back"] == 1
    assert collector.kids[100][0] == "W"
    assert caplog.records == []
    copy = collector.measured()
    copy["W"]["p1"] = 99
    assert collector.measured()["W"]["p1"] == 1


def test_loss_queries_do_not_create_fake_events_lost() -> None:
    class Backend:
        def loss(self):
            raise OSError(87, "failed")

    collector = etw.Collector(Backend(), lambda _event: None)
    collector.poll_loss()
    assert collector.counters.events_lost == 0
    assert collector.counters.query_failures == 1
    assert collector.counters.gap
    collector.counters.truncated = 2
    assert etw.EtwObserver._loss_total(collector.counters) == 0


def test_stop_is_idempotent_and_drains_a_late_callback() -> None:
    class Backend:
        calls = 0

        def stop(self):
            self.calls += 1

    seen = []
    backend = Backend()
    collector = etw.Collector(backend, lambda event: seen.append(event.pid))
    collector._stop.set()

    class Consumer:
        emitted = False

        def is_alive(self):
            if not self.emitted:
                self.emitted = True
                collector.callback(raw(1, 100, parent=os.getpid()))
            return False

    collector._consumer = Consumer()
    collector._aggregate()
    assert seen == [100]
    collector._consumer = None
    collector._stop.clear()
    collector.stop()
    collector.stop()
    assert backend.calls == 1


def test_periodic_flush_runs_only_when_requested(monkeypatch) -> None:
    now = [0.0]
    monkeypatch.setattr(etw.time, "monotonic", lambda: now[0])

    class Backend:
        flushes = 0

        def flush(self):
            self.flushes += 1
            return 0

    backend = Backend()
    collector = etw.Collector(backend, lambda _event: None)
    collector.flush_every = 1.0
    calls = [0]

    def empty(*, timeout):
        calls[0] += 1
        now[0] += 0.6
        if calls[0] == 4:
            collector._stop.set()
        raise queue.Empty

    monkeypatch.setattr(collector.queue, "get", empty)
    collector._aggregate()
    assert backend.flushes == 1
    assert list(collector._flush_results) == [0]


def test_check_runs_both_children_and_flushes_at_five_and_six(monkeypatch) -> None:
    now = [0.0]
    monkeypatch.setattr(etw.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(etw.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    observer = etw.EtwObserver(lambda _path: None)
    observer.state = "checking"
    spawned = []

    class Child:
        def __init__(self, pid):
            self.pid = pid

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    def popen(argv, **kwargs):
        spawned.append((now[0], argv, kwargs))
        pid = 100 + len(spawned)
        if len(spawned) == 2:
            event = replace(raw(1, pid, parent=os.getpid()), phase="B")
            observer._check_raw_event(event, etw.parse_event(event))
            observer._parsed(etw.parse_event(event))
        return Child(pid)

    class Collector:
        phase = "W"
        flush_every = 0.0

        def __init__(self):
            self.flushes = []
            self.queue = queue.Queue()
            self.priority_queue = queue.Queue()

        def set_phase(self, phase):
            self.phase = phase
            return True

        def flush(self):
            self.flushes.append(now[0])
            return 0

        def measured(self):
            return {}

        def session_stats(self):
            return {}

    collector = Collector()
    observer.collector = collector
    monkeypatch.setattr(etw.subprocess, "Popen", popen)
    assert observer._check_schema(collector) == ""
    assert len(spawned) == 2
    assert spawned[0][0] == 0 and 3 <= spawned[1][0] < 3.1
    assert len(collector.flushes) == 2
    assert 5 <= collector.flushes[0] < 5.1
    assert 6 <= collector.flushes[1] < 6.1
    assert observer._pass_phase == "B"
    assert collector.flush_every == 0
    assert now[0] == 7.0


def test_flush_only_match_enables_periodic_assist(monkeypatch) -> None:
    now = [0.0]
    monkeypatch.setattr(etw.time, "monotonic", lambda: now[0])
    observer = etw.EtwObserver(lambda _path: None)
    observer.state = "checking"

    class Child:
        def __init__(self, pid):
            self.pid = pid

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    spawned = []
    def popen(*_args, **_kwargs):
        pid = 100 + len(spawned)
        spawned.append(pid)
        return Child(pid)

    class Collector:
        phase = "W"
        flush_every = 0.0

        def __init__(self):
            self.queue = queue.Queue()
            self.priority_queue = queue.Queue()

        def flush(self):
            if now[0] >= 5 and spawned:
                event = replace(raw(1, spawned[0], parent=os.getpid()), phase="F")
                observer._check_raw_event(event, etw.parse_event(event))
                observer._parsed(etw.parse_event(event))
            return 0

        def set_phase(self, phase):
            self.phase = phase
            return True

        def measured(self):
            return {}

        def session_stats(self):
            return {}

    collector = Collector()
    observer.collector = collector
    monkeypatch.setattr(etw.subprocess, "Popen", popen)
    monkeypatch.setattr(etw.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    assert observer._check_schema(collector) == ""
    assert observer._pass_phase == "F"
    assert observer.flush_assist and collector.flush_every == 1.0


def test_raw_child_start_with_wrong_parent_is_schema_mismatch(monkeypatch) -> None:
    now = [0.0]
    monkeypatch.setattr(etw.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(etw.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    observer = etw.EtwObserver(lambda _path: None)
    observer.state = "checking"

    class Child:
        def __init__(self, pid):
            self.pid = pid

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    count = [0]
    def popen(*_args, **_kwargs):
        count[0] += 1
        pid = 100 + count[0]
        if count[0] == 1:
            event = raw(1, pid, parent=os.getpid() + 1)
            observer._check_raw_event(event, etw.parse_event(event))
            observer._parsed(etw.parse_event(event))
        return Child(pid)

    monkeypatch.setattr(etw.subprocess, "Popen", popen)
    assert observer._check_schema(None) == "schema_process_mismatch"


def test_observer_connects_then_enables_and_reports_status(caplog) -> None:
    class Backend:
        stopped = False
        enabled = False

        def start(self, callback):
            self.callback = callback
            return etw.StartResult("STARTED")

        def process(self):
            self.callback(etw.RawEvent(etw.EVENT_TRACE_CLASS, 5, 0, 0, 0, 1, b""))

        def enable(self):
            assert observer.collector.counters.callbacks == 1
            self.enabled = True
            return etw.StartResult("STARTED")

        def loss(self):
            return 0, 0, 0

        def stop(self):
            self.stopped = True

    backend = Backend()

    def check(collector):
        assert backend.enabled and collector.phase == "W"
        collector.counters.truncated = 2
        collector.counters.query_failures = 1
        return ""

    observer = etw.EtwObserver(lambda _path: None,
                               backend_factory=lambda _guid: backend, check=check)
    with caplog.at_level(logging.WARNING):
        observer.start()
    assert observer.state == "on"
    assert observer.status()["etw_truncated"] == 2
    assert observer.status()["etw_query_failures"] == 1
    assert observer.status()["etw_events_lost"] == 0
    assert observer.status()["etw_flush_assist"] is False
    assert observer.status()["etw_check_phase"] == ""  # the stub check matched no child
    assert any(row.message.startswith("etw check: connect ") and
               '"path": "callback"' in row.message for row in caplog.records)
    assert any(row.message.startswith("etw check: result ") and
               '"result": "pass"' in row.message for row in caplog.records)
    observer.stop()


def test_failed_enable_stops_and_names_state() -> None:
    class Backend:
        stopped = False

        def start(self, callback):
            self.callback = callback
            return etw.StartResult("STARTED")

        def process(self):
            self.callback(etw.RawEvent(etw.EVENT_TRACE_CLASS, 5, 0, 0, 0, 1, b""))

        def enable(self):
            return etw.StartResult("DENIED", 5)

        def loss(self):
            return 0, 0, 0

        def stop(self):
            self.stopped = True

    backend = Backend()
    observer = etw.EtwObserver(lambda _path: None, backend_factory=lambda _guid: backend,
                               check=lambda _collector: "")
    observer.start()
    assert observer.state == "enable_denied_5" and backend.stopped


# Review fixes (Claude).


def test_status_reports_the_phase_that_passed_not_the_last_one() -> None:
    observer = etw.EtwObserver(lambda _path: None)
    observer.check_phase, observer._pass_phase = "F", "W"
    assert observer.status()["etw_check_phase"] == "W"
    observer._pass_phase = None
    assert observer.status()["etw_check_phase"] == ""


def test_truncated_but_delivered_events_are_no_gap_and_dropped_ones_are() -> None:
    counters = etw.Counters(truncated=3)
    assert not counters.gap
    collector = etw.Collector(None, lambda _event: None)
    collector.callback(etw.RawEvent(etw.PROCESS_CLASS, 1, 4, 0, 0, 1, bytes(etw.MAX_PAYLOAD + 1)))
    assert collector.counters.queue_drops == 1 and collector.counters.gap


def test_enable_failing_after_a_service_stop_leaves_the_state_off() -> None:
    class Backend:
        def start(self, callback):
            self.callback = callback
            return etw.StartResult("STARTED")

        def process(self):
            self.callback(etw.RawEvent(etw.EVENT_TRACE_CLASS, 5, 0, 0, 0, 1, b""))

        def enable(self):
            observer.stop()
            return etw.StartResult("ERROR")

        def loss(self):
            return 0, 0, 0

        def stop(self):
            return None

    observer = etw.EtwObserver(lambda _path: None, backend_factory=lambda _guid: Backend(),
                               check=lambda _collector: "")
    observer.start()
    assert observer.state == "off"


def test_a_stop_during_the_check_is_logged_once(caplog) -> None:
    import threading

    entered, release = threading.Event(), threading.Event()

    class Backend:
        def start(self, callback):
            return etw.StartResult("STARTED")

        def process(self):
            return None

        def loss(self):
            return 0, 0, 0

        def stop(self):
            return None

    def check(_collector):
        entered.set()
        release.wait(2)
        return ""

    observer = etw.EtwObserver(lambda _path: None, backend_factory=lambda _guid: Backend(), check=check)
    thread = threading.Thread(target=observer.start)
    with caplog.at_level(logging.WARNING):
        thread.start()
        assert entered.wait(1)
        observer.stop()
        release.set()
        thread.join(2)
    assert not thread.is_alive()
    stops = [row for row in caplog.records if row.message.startswith("etw check: stop ")]
    assert len(stops) == 1
