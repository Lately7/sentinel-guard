"""Regression tests for optional ETW observation; all events are synthetic."""

import os
import struct
import sys
import threading
import uuid

import pytest

from sentinel.service import backend, etw, procwatch, verify


def process_payload(pid=123, version=4, name=b"python.exe", command="python -I", subauth=(32, 544)):
    # Canned Process_TypeGroup1 x64 V3/V4 bytes built from the documented layout, not captured.
    fixed = struct.pack("<QIIIIQ", 0, pid, 0, 0, 0, 0)
    if version == 4:
        fixed += struct.pack("<I", 0)
    sid = bytes((1, len(subauth))) + b"\0\0\0\0\0\5"
    sid += b"".join(struct.pack("<I", value) for value in subauth)
    return fixed + sid + name + b"\0" + command.encode("utf-16-le") + b"\0\0"


def test_documented_process_v3_v4_sid_name_and_bounded_command():
    for version in (3, 4):
        raw = etw.RawEvent(etw.PROCESS_PROVIDER, 1, version, 999, 1, 42,
                           process_payload(version=version, command="x" * 400))
        parsed = etw.parse_event(raw)
        assert (parsed.pid, parsed.path, parsed.image_name, len(parsed.command_line)) == (123, "", "python.exe", 256)
        observer = etw.EtwObserver(lambda path: None)
        observer.state = "checking"
        observer._parsed(parsed)
        assert all("xxxxx" not in value for value in observer.status().values()
                   if isinstance(value, str))
        assert etw.parse_event(raw.__class__(etw.PROCESS_CLASS, raw.opcode, version,
                                             raw.pid, raw.tid, raw.timestamp, raw.payload)).image_name == "python.exe"
        assert etw.parse_event(raw.__class__(raw.provider, raw.opcode, version, raw.pid,
                                             raw.tid, raw.timestamp, raw.payload[:35])) is None


def test_collector_counts_parsed_events_and_keeps_queue_loss_visible():
    seen = []
    collector = etw.Collector(None, seen.append, capacity=1)
    raw = etw.RawEvent(etw.PROCESS_PROVIDER, 1, 4, 9, 1, 1,
                       process_payload())
    collector.callback(raw)
    collector.callback(raw)
    assert collector.counters.queue_drops == 1
    assert collector.counters.gap
    collector._stop.set()
    collector._aggregate()
    assert collector.counters.parsed == 1


def test_failed_delivery_counts_as_gap():
    def broken(event):
        raise ValueError("synthetic")

    collector = etw.Collector(None, broken, capacity=1)
    collector.callback(etw.RawEvent(etw.PROCESS_PROVIDER, 1, 4, 9, 1, 1,
                                    process_payload()))
    collector._stop.set()
    collector._aggregate()
    assert collector.counters.handler_failures == 1
    assert collector.counters.gap


def test_failed_schema_check_stops_session_and_never_offers(caplog):
    class Fake:
        stopped = False

        def start(self, callback):
            self.callback = callback
            return etw.StartResult("STARTED")

        def process(self):
            return None

        def loss(self):
            return (0, 0, 0)

        def stop(self):
            self.stopped = True

    fake = Fake()
    offers = []
    observer = etw.EtwObserver(offers.append, backend_factory=lambda guid: fake,
                               check=lambda collector: "schema_process_missing")
    observer.start()
    assert observer.status()["etw"] == "schema_process_missing"
    assert fake.stopped
    assert offers == []
    assert any(record.message.startswith("etw check: schema_process_missing counts")
               for record in caplog.records)


def test_verified_process_event_only_offers_image_and_file_callback():
    class Fake:
        def start(self, callback):
            self.callback = callback
            return etw.StartResult("STARTED")

        def process(self):
            return None

        def loss(self):
            return (0, 0, 0)

        def stop(self):
            return None

    fake = Fake()
    offers, files = [], []
    observer = etw.EtwObserver(offers.append, on_file_event=files.append,
                               backend_factory=lambda guid: fake, check=lambda collector: "")
    observer._resolve_process = lambda pid: "C:\\safe.exe"
    observer.start()
    observer._parsed(etw.ParsedEvent("process_start", 12, 0, image_name="safe.exe"))
    observer._parsed(etw.ParsedEvent("write", 12, 0, file_object=1))
    assert offers == ["C:\\safe.exe"]
    assert [item.kind for item in files] == ["process_start", "write"]
    assert observer.status()["etw"] == "on"
    observer.stop()


def test_verify_reports_optional_etw_as_skip_or_pass():
    assert verify._etw({"observation": {"etw": "on", "etw_events_parsed": 2}}) == (True, "đã phân tích 2 sự kiện, mất 0")
    assert verify._etw({"observation": {"etw": "schema_file_missing"}}) == (None, "ETW tắt: schema_file_missing, mất 0")


def test_live_check_requires_own_rundown_and_child_start(monkeypatch):
    class Child:
        pid = 123

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    observer = etw.EtwObserver(lambda path: None)
    observer.state = "checking"
    def popen(*args, **kwargs):
        observer._parsed(etw.ParsedEvent(
            "process_start", 123, 0, image_name=etw.ntpath.basename(sys.executable)))
        return Child()
    monkeypatch.setattr(etw.subprocess, "Popen", popen)
    observer._parsed(etw.ParsedEvent(
        "process_rundown", os.getpid(), 0,
        image_name=etw.ntpath.basename(sys.executable)))
    assert observer._check_schema(None) == ""
    missing = etw.EtwObserver(lambda path: None)
    missing.state = "checking"
    monkeypatch.setattr(etw.time, "monotonic", iter((0.0, 6.0)).__next__)
    assert missing._check_schema(None) == "schema_process_missing"


def test_orphan_is_recovered_before_new_session(monkeypatch):
    calls = []
    old = uuid.uuid4()

    def cleanup(guid, *, stored_name):
        calls.append((guid, stored_name))
        return etw.StartResult("STOPPED")

    monkeypatch.setattr(etw, "cleanup_orphan", cleanup)

    class Fake:
        def start(self, callback):
            return etw.StartResult("UNAVAILABLE")

        def stop(self):
            return None

    saved = []
    observer = etw.EtwObserver(lambda path: None, backend_factory=lambda guid: Fake(),
                               read_guid=lambda: str(old), write_guid=saved.append)
    observer.start()
    assert calls == [(old, etw.SESSION_NAME)]
    assert len(saved) == 1 and saved[0] != str(old)


def test_machine_observers_keeps_sampler_and_uses_offer(monkeypatch):
    monkeypatch.setattr(backend.scope, "fixed_drives", lambda: [])

    class Db:
        def get_meta(self, key, default):
            return default

        def set_meta(self, key, value):
            return None

    class Product:
        db = Db()
        rescans = None

        def __init__(self):
            self.offers = []

        def observe(self, path, reason, fresh):
            self.offers.append((path, reason, fresh))
            return True

    product = Product()
    observer = backend._machine_observers(product)
    assert observer.processes is not None
    monkeypatch.setattr(observer, "wanted", lambda path: True)
    observer.etw.state = "on"
    observer.etw._resolve_process = lambda pid: "C:\\safe.exe"
    observer.etw._parsed(etw.ParsedEvent("process_start", 123, 0, image_name="safe.exe"))
    assert product.offers == [("C:\\safe.exe", "process", False)]


def test_status_contains_etw_state_and_loss():
    class Observer:
        def report(self):
            return {"prevention": "none"}

    fake = type("Backend", (), {})()
    fake.observers = Observer()
    fake.observers.etw = type("Etw", (), {"status": lambda self: {
        "etw": "on", "etw_events_parsed": 8, "etw_events_lost": 2, "etw_gap": True}})()
    fake.barrier = type("Barrier", (), {"current": lambda self: object()})()
    fake.db = type("Db", (), {"quarantine_items": lambda self: [],
                              "get_meta": lambda self, key, default: default,
                              "allow_version": lambda self: "0"})()
    fake._asked_lane = type("Lane", (), {"stalled": 0})()
    fake._observed_lane = type("Lane", (), {"stalled": 0})()
    fake._worker_down_skipped = 0
    fake.scanner = type("Scanner", (), {"isolation": None})()
    assert backend.ProductBackend.status(fake)["observation"]["etw_gap"] is True


def test_stop_shares_one_five_second_join_budget(monkeypatch):
    class Thread:
        def __init__(self):
            self.waited = None

        def join(self, timeout):
            self.waited = timeout

    class Backend:
        def stop(self):
            return None

    collector = etw.Collector(Backend(), lambda event: None)
    collector._consumer, collector._aggregator = Thread(), Thread()
    monkeypatch.setattr(etw.time, "monotonic", iter((0.0, 2.0, 4.0)).__next__)
    collector.stop()
    assert collector._consumer.waited == 3.0
    assert collector._aggregator.waited == 1.0


def test_process_resolution_uses_sampler_key_and_rejects_native_paths(monkeypatch):
    key = procwatch.ProcessKey(123, 456)
    monkeypatch.setattr(procwatch, "windows_snapshot", lambda: procwatch.SnapshotResult((key,)))
    seen = []
    monkeypatch.setattr(procwatch, "windows_resolve", lambda value: (seen.append(value) or "C:\\safe.exe", (1, 2)))
    observer = etw.EtwObserver(lambda path: None)
    assert observer._resolve_process(123) == "C:\\safe.exe"
    assert seen == [key]
    monkeypatch.setattr(procwatch, "windows_resolve", lambda value: ("\\Device\\HarddiskVolume1\\safe.exe", (1, 2)))
    try:
        observer._resolve_process(123)
    except OSError:
        pass
    else:
        assert False, "native path was accepted"
    monkeypatch.setattr(procwatch, "windows_snapshot", lambda: procwatch.SnapshotResult((), denied=(123,)))
    try:
        observer._resolve_process(123)
    except OSError as error:
        assert not isinstance(error, ProcessLookupError)
    else:
        assert False, "inaccessible process was counted as an exit"


def test_process_exit_counted_and_unresolved_path_never_offered():
    offers = []
    observer = etw.EtwObserver(offers.append)
    observer.state = "on"
    def gone(pid):
        raise ProcessLookupError(pid)
    observer._resolve_process = gone
    observer._parsed(etw.ParsedEvent("process_start", 123, 0, image_name="safe.exe"))
    assert offers == []
    assert observer.status()["etw_exits_before_resolution"] == 1
    observer._resolve_process = lambda pid: "C:\\different.exe"
    observer._parsed(etw.ParsedEvent("process_start", 123, 0, image_name="safe.exe"))
    assert offers == []


def test_service_start_does_not_wait_for_check_and_stop_cancels_it(monkeypatch):
    monkeypatch.setattr(backend.Observers, "start", lambda self: None)
    monkeypatch.setattr(backend.Observers, "stop", lambda self: None)
    monkeypatch.setattr(backend.scope, "fixed_drives", lambda: [])

    class Db:
        def get_meta(self, key, default):
            return default
        def set_meta(self, key, value):
            return None

    class Product:
        db = Db()
        rescans = None
        def observe(self, path, reason, fresh):
            return True

    machine = backend._machine_observers(Product())
    entered, release = threading.Event(), threading.Event()
    def slow_check():
        entered.set()
        release.wait(2)
    machine.etw.start = slow_check
    machine.etw.stop = release.set
    machine.start()
    assert entered.wait(1)
    machine.stop()
    assert release.is_set()


def test_stop_during_check_cannot_turn_on_or_leave_session():
    entered, release = threading.Event(), threading.Event()
    class Fake:
        stopped = False
        def start(self, callback):
            return etw.StartResult("STARTED")
        def process(self):
            return None
        def loss(self):
            return (0, 0, 0)
        def stop(self):
            self.stopped = True
    fake = Fake()
    def check(collector):
        entered.set()
        release.wait(2)
        return ""
    observer = etw.EtwObserver(lambda path: None, backend_factory=lambda guid: fake, check=check)
    thread = threading.Thread(target=observer.start)
    thread.start()
    assert entered.wait(1)
    observer.stop()
    release.set()
    thread.join(2)
    assert not thread.is_alive()
    assert fake.stopped and observer.state == "off"


def test_unrelated_queue_drop_does_not_fail_successful_check():
    class Fake:
        stopped = False
        def start(self, callback):
            return etw.StartResult("STARTED")
        def process(self):
            return None
        def loss(self):
            return (0, 0, 0)
        def stop(self):
            self.stopped = True
    fake = Fake()
    def check(collector):
        collector.counters.queue_drops = 1
        return ""
    observer = etw.EtwObserver(lambda path: None, backend_factory=lambda guid: fake, check=check)
    observer.start()
    assert observer.state == "on" and not fake.stopped
    observer.stop()


def test_observer_does_not_enable_io_after_check():
    class Fake:
        controls = []
        def start(self, callback):
            return etw.StartResult("STARTED")
        def process(self):
            return None
        def loss(self):
            return (0, 0, 0)
        def set_file_events(self, enabled):
            self.controls.append(enabled)
            return True
        def stop(self):
            return None
    fake = Fake()
    observer = etw.EtwObserver(lambda path: None, backend_factory=lambda guid: fake,
                               check=lambda collector: "")
    observer.start()
    assert fake.controls == []
    assert observer.status()["etw_file_events"] == "off"
    observer.stop()


def test_native_io_control_uses_disable_provider_code():
    class Api:
        codes = []
        def EnableTraceEx2(self, handle, guid, code, level, keywords, match_all, timeout, params):
            self.codes.append(code)
            return 0
    api = Api()
    native = etw.NativeBackend()
    native._api = api
    native.owned = True
    assert native.set_file_events(False)
    assert native.set_file_events(True)
    assert api.codes == [0, 1]


def test_failed_check_logs_only_own_bounded_payloads(caplog, monkeypatch):
    observer = etw.EtwObserver(lambda path: None)
    observer.state = "checking"
    own = etw.RawEvent(etw.PROCESS_PROVIDER, 3, 4, 123, 1, 0,
                       process_payload(pid=os.getpid(), command="secret"))
    other = etw.RawEvent(etw.PROCESS_PROVIDER, 3, 4, 456, 1, 0,
                         process_payload(pid=456, command="private"))
    observer._check_raw_event(own, etw.parse_event(own))
    observer._check_raw_event(other, etw.parse_event(other))
    observer._log_check_failure("no_start_events")
    lines = [record.message for record in caplog.records if record.message.startswith("etw check:")]
    assert 1 <= len(lines) < 12
    assert any("process/3" in line for line in lines)
    assert "private" not in " ".join(lines)
    assert other.payload[:160].hex() not in " ".join(lines)
    assert "secret" not in " ".join(lines)


def test_file_rate_guard_disables_io_retries_and_reports_cost(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(etw.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(etw, "FILE_RATE_LIMIT", 1)
    monkeypatch.setattr(etw, "FILE_RATE_SECONDS", 2.0)
    class Fake:
        controls = []
        def set_file_events(self, enabled):
            self.controls.append(enabled)
            return True
    fake = Fake()
    collector = etw.Collector(fake, lambda event: None, capacity=16)
    collector.after_check(True)
    raw = etw.RawEvent(etw.IO_PROVIDER, 68, 3, 1, 1, 1, b"x")
    for second in range(1, 4):
        collector.callback(raw)
        collector.callback(raw)
        now[0] = float(second)
        collector.callback(raw)
    collector._file_rate_guard()
    assert fake.controls == [False]
    assert collector.file_events == "guarded" and collector.counters.guarded_gaps == 1
    assert collector.counters.gap
    assert collector.counters.callbacks_per_second > 1
    observer = etw.EtwObserver(lambda path: None)
    observer.collector = collector
    assert observer.status()["etw_events_per_second"] > 1
    assert observer.status()["etw_callback_cpu_s"] >= 0
    now[0] = 603.0
    collector._file_rate_guard()
    assert fake.controls == [False, True]
    assert collector.file_events == "on"
    assert observer.status()["etw_events_per_second"] == 0
    collector._guard_requested = True
    now[0] = 604.0
    collector._file_rate_guard()
    assert collector._retry_at == 1804.0
    assert collector._retry_delay == 2400.0
    collector._retry_delay = etw.FILE_RETRY_MAX
    now[0] = 1804.0
    collector._file_rate_guard()
    collector._guard_requested = True
    now[0] = 1805.0
    collector._file_rate_guard()
    assert collector._retry_delay == etw.FILE_RETRY_MAX


def test_a_device_path_becomes_the_drive_path_the_rest_of_the_product_uses():
    from sentinel.service import etw

    devices = {"\\device\\harddiskvolume3": "C:"}
    assert etw.on_drive("\\Device\\HarddiskVolume3\\Users\\u\\a.docx", devices) == "C:\\Users\\u\\a.docx"
    assert etw.on_drive("\\Device\\HarddiskVolume9\\x.bin", devices) == "\\Device\\HarddiskVolume9\\x.bin"
    assert etw.on_drive("C:\\Users\\u\\a.docx", devices) == "C:\\Users\\u\\a.docx"


@pytest.mark.skipif(os.name != "nt", reason="the real device names")
def test_this_machine_has_a_device_for_its_system_drive():
    from sentinel.service import etw

    devices = etw.device_map()
    system = os.environ.get("SystemDrive", "C:")
    assert system in devices.values()
    device = next(name for name, drive in devices.items() if drive == system)
    assert etw.on_drive(device + "\\Windows", devices) == system + "\\Windows"


def test_scoring_hears_about_processes_as_well_as_files():
    from sentinel.service import etw

    heard = []
    observer = etw.EtwObserver(lambda path: None, on_file_event=heard.append)
    observer.state = "on"
    observer._resolve_process = lambda pid: "C:\\Program Files\\A\\averyveryverylongname.exe"
    start = etw.ParsedEvent("process_start", 42, 1, image_name="averyveryverylo")
    stop = etw.ParsedEvent("process_stop", 42, 1)
    observer._parsed(start)
    observer._parsed(stop)
    assert heard == [start, stop]


def test_a_short_name_cut_by_the_kernel_still_offers_the_process():
    from sentinel.service import etw

    offered = []
    observer = etw.EtwObserver(offered.append)
    observer.state = "on"
    observer._resolve_process = lambda pid: "C:\\Program Files\\A\\averyveryverylongname.exe"
    observer._parsed(etw.ParsedEvent("process_start", 42, 1, image_name="averyveryverylo"))
    assert offered == ["C:\\Program Files\\A\\averyveryverylongname.exe"]
    observer._resolve_process = lambda pid: "C:\\Program Files\\A\\other.exe"
    observer._parsed(etw.ParsedEvent("process_start", 43, 1, image_name="averyveryverylo"))
    assert len(offered) == 1, "a reused pid running something else is not this process"
