"""Regression tests for the process-only ETW session; payloads are synthetic."""

import ctypes
import logging
import os
import struct
import sys
import uuid

from sentinel.service import backend, etw, verify


def process_payload(pid: int, *, version: int = 4, name: bytes = b"python.exe") -> bytes:
    # Process_TypeGroup1 x64 V3/V4 layout from Microsoft's MOF, not captured bytes.
    fixed = struct.pack("<QIIIIQ", 0, pid, 0, 0, 0, 0)
    if version == 4:
        fixed += struct.pack("<I", 0)
    sid = bytes((1, 1)) + b"\0\0\0\0\0\5" + struct.pack("<I", 18)
    return fixed + sid + name + b"\0" + "python -I".encode("utf-16-le") + b"\0\0"


def raw_process(opcode: int, pid: int, *, version: int = 4,
                provider: uuid.UUID = etw.PROCESS_CLASS) -> etw.RawEvent:
    return etw.RawEvent(provider, opcode, version, 999, 1, 42,
                        process_payload(pid, version=version))


def test_rundown_parses_as_process_rundown_without_becoming_live_start() -> None:
    for version in (3, 4):
        event = etw.parse_event(raw_process(3, os.getpid(), version=version))
        assert event is not None
        assert (event.kind, event.pid, event.image_name) == (
            "process_rundown", os.getpid(), "python.exe")


def test_check_requires_own_rundown_then_child_start(monkeypatch) -> None:
    class Child:
        pid = 12345

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    spawned = []
    emit_start = [True]

    def popen(argv, **kwargs):
        spawned.append((argv, kwargs))
        if emit_start[0]:
            observer._parsed(etw.parse_event(raw_process(1, Child.pid)))
        return Child()

    monkeypatch.setattr(etw.subprocess, "Popen", popen)
    observer = etw.EtwObserver(lambda _path: None)
    observer.state = "checking"
    observer._parsed(etw.parse_event(raw_process(3, os.getpid())))
    assert observer._check_schema(None) == ""
    assert len(spawned) == 1
    assert spawned[0][0][0] == sys.executable
    assert spawned[0][1]["shell"] is False

    observer._checking.clear()
    emit_start[0] = False
    tick = iter(range(100))
    monkeypatch.setattr(etw.time, "monotonic", lambda: float(next(tick)))
    monkeypatch.setattr(etw.time, "sleep", lambda _seconds: None)
    assert observer._check_schema(None) == "no_start_events"


def test_own_rundown_survives_a_rundown_longer_than_the_check_buffer(monkeypatch) -> None:
    # A desktop runs 300+ processes; the own entry arrives early in the burst.
    class Child:
        pid = 12345

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    observer = etw.EtwObserver(lambda _path: None)
    observer.state = "checking"
    monkeypatch.setattr(etw.subprocess, "Popen", lambda *_args, **_kwargs: (
        observer._parsed(etw.parse_event(raw_process(1, Child.pid))), Child())[1])
    observer._parsed(etw.parse_event(raw_process(3, os.getpid())))
    for pid in range(20_000, 20_400):
        observer._parsed(etw.parse_event(raw_process(3, pid)))
    tick = iter(range(100))
    monkeypatch.setattr(etw.time, "monotonic", lambda: float(next(tick)))
    monkeypatch.setattr(etw.time, "sleep", lambda _seconds: None)
    assert observer._check_schema(None) == ""


def test_native_session_enables_only_process_provider() -> None:
    class Api:
        def __init__(self):
            self.enabled = []
            self.OpenTraceW = lambda *_args: 1

        def StartTraceW(self, *_args):
            return 0

        def EnableTraceEx2(self, _handle, guid, code, level, keywords,
                           _match_all, _timeout, _params):
            provider = uuid.UUID(bytes_le=bytes(ctypes.cast(
                guid, ctypes.POINTER(etw.GUID)).contents))
            self.enabled.append((provider, code, level, keywords.value))
            return 0

    native = etw.NativeBackend()
    api = Api()
    native._api = api
    assert native.start(lambda _event: None).status == "STARTED"
    assert api.enabled == [(etw.PROCESS_PROVIDER, 1, 0, etw.PROCESS_KEYWORDS)]
    props = etw.EVENT_TRACE_PROPERTIES.from_buffer(etw._properties())
    assert (props.BufferSize, props.MinimumBuffers, props.MaximumBuffers,
            props.FlushTimer, props.LogFileMode) == (64, 16, 64, 1, 0x02000100)


def test_failed_check_logs_only_own_dcs_start_bytes(caplog) -> None:
    observer = etw.EtwObserver(lambda _path: None)
    observer.state = "checking"
    own = raw_process(3, os.getpid())
    other = raw_process(3, os.getpid() + 1)
    child = raw_process(1, os.getpid())
    for raw in (own, other, child, own):
        observer._check_raw_event(raw, etw.parse_event(raw))
    with caplog.at_level(logging.WARNING):
        observer._log_check_failure("no_start_events")
    lines = [record.message for record in caplog.records if record.message.startswith("etw check:")]
    assert lines[0].startswith("etw check: no_start_events counts ")
    assert len(lines) == 3
    assert all("process/3 " in line for line in lines[1:])
    assert own.payload[:160].hex() in lines[1]
    assert other.payload[:160].hex() not in " ".join(lines)


def test_check_loss_is_separate_and_status_explains_file_source() -> None:
    class Fake:
        loss_count = 0

        def start(self, _callback):
            return etw.StartResult("STARTED")

        def process(self):
            return None

        def loss(self):
            return self.loss_count, 0, 0

        def stop(self):
            return None

    fake = Fake()

    def check(_collector):
        fake.loss_count = 7
        return "no_start_events"

    observer = etw.EtwObserver(lambda _path: None, backend_factory=lambda _guid: fake,
                               check=check)
    observer.start()
    status = observer.status()
    assert status["etw"] == "no_start_events"
    assert status["etw_check_events_lost"] == 7
    assert status["etw_file_events"] == "off"
    assert status["etw_file_events_reason"] == "Python không theo kịp tốc độ sự kiện tệp"
    assert verify._etw({"observation": status}) == (
        None, "ETW tắt: no_start_events, mất 7, mất lúc kiểm tra 7")


def test_shadow_waits_for_file_source_without_counting_days(monkeypatch) -> None:
    monkeypatch.setattr(backend.scope, "fixed_drives", lambda: [])

    class Db:
        def get_meta(self, _key, default):
            return default

        def set_meta(self, _key, _value):
            return None

    class Product:
        db = Db()
        rescans = None

        def observe(self, _path, _reason, _fresh):
            return True

    machine = backend._machine_observers(Product())
    assert machine.etw.on_file_event is None
    report = machine.report()["shadow"]
    assert report["state"] == "waiting_for_file_events"
    assert report["days_observed"] is None


def test_verify_pass_reports_loss_when_etw_is_on() -> None:
    assert verify._etw({"observation": {"etw": "on", "etw_events_parsed": 2,
                                        "etw_events_lost": 3,
                                        "etw_check_events_lost": 1}}) == (
        True, "đã phân tích 2 sự kiện, mất 3, mất lúc kiểm tra 1")
