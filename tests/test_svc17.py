"""Regression tests for the process-only ETW session.

The canned payloads follow the layout of the one captured event below: a Start of the
service's own check child, logged by the owner's install on 2026-11-03.
"""

import ctypes
import logging
import os
import struct
import sys
import uuid
from dataclasses import replace

from sentinel.service import backend, etw, verify

# The first 160 bytes of a real Process Start (opcode 1): pid 14868, parent 31764 (the
# service), SYSTEM, python.exe, and the start of its command line. Captured, not built.
CAPTURED_START = bytes.fromhex(
    "808024c388e7ffff143a0000147c0000000000000301000000a05bcf070000000000000000a8b0ff84b5ffff00000000"
    "00000000010100000000000512000000707974686f6e2e65786500220043003a005c00500072006f006700720061006d"
    "002000460069006c00650073005c00530065006e00740069006e0065006c00470075006100720064005c007600650072"
    "00730069006f006e0073005c0030002e")


def process_payload(pid: int, *, version: int = 4, name: bytes = b"python.exe", parent: int = 0) -> bytes:
    fixed = struct.pack("<QIIIIQ", 0, pid, parent, 0, 0, 0)
    if version == 4:
        fixed += struct.pack("<I", 0)
    token_user = struct.pack("<QQ", 0xFFFFB584FFB0A800, 0)
    sid = bytes((1, 1)) + b"\0\0\0\0\0\5" + struct.pack("<I", 18)
    return fixed + token_user + sid + name + b"\0" + "python -I".encode("utf-16-le") + b"\0\0"


def raw_process(opcode: int, pid: int, *, version: int = 4, parent: int = 0,
                provider: uuid.UUID = etw.PROCESS_CLASS, payload: bytes | None = None) -> etw.RawEvent:
    return etw.RawEvent(provider, opcode, version, 999, 1, 42,
                        payload if payload is not None else process_payload(pid, version=version, parent=parent))


class Child:
    pid = 12345

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


def deliver(observer, event: etw.RawEvent, phase: str = "W") -> None:
    # The aggregator runs on_raw, which keeps the callback-time phase, before on_event.
    event = replace(event, phase=phase)
    parsed = etw.parse_event(event)
    observer._check_raw_event(event, parsed)
    observer._parsed(parsed)


def fast_clock(monkeypatch) -> None:
    now = [0.0]
    monkeypatch.setattr(etw.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(etw.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))


def test_the_captured_start_parses_with_its_pid_parent_and_image() -> None:
    event = etw.parse_event(raw_process(1, 0, payload=CAPTURED_START))
    assert event is not None
    assert (event.kind, event.pid, event.parent_pid, event.image_name) == (
        "process_start", 14868, 31764, "python.exe")
    assert event.command_line.startswith('"C:\\Program Files\\SentinelGuard\\versions\\0')


def test_rundown_parses_as_process_rundown_without_becoming_live_start() -> None:
    for version in (3, 4):
        event = etw.parse_event(raw_process(3, os.getpid(), version=version))
        assert event is not None
        assert (event.kind, event.pid, event.image_name) == (
            "process_rundown", os.getpid(), "python.exe")


def test_the_check_passes_on_its_child_start_alone(monkeypatch) -> None:
    spawned = []
    observer = etw.EtwObserver(lambda _path: None)
    observer.state = "checking"

    def popen(argv, **kwargs):
        spawned.append((argv, kwargs))
        deliver(observer, raw_process(1, Child.pid, parent=os.getpid()))
        return Child()

    monkeypatch.setattr(etw.subprocess, "Popen", popen)
    fast_clock(monkeypatch)
    assert observer._check_schema(None) == ""
    assert len(spawned) == 2
    assert spawned[0][0][0] == sys.executable
    assert spawned[0][1]["shell"] is False


def test_no_start_and_an_unreadable_start_are_told_apart(monkeypatch) -> None:
    quiet = etw.EtwObserver(lambda _path: None)
    quiet.state = "checking"
    monkeypatch.setattr(etw.subprocess, "Popen", lambda *_args, **_kwargs: Child())
    fast_clock(monkeypatch)
    assert quiet._check_schema(None) == "no_start_events"

    garbled = etw.EtwObserver(lambda _path: None)
    garbled.state = "checking"
    unreadable = raw_process(1, Child.pid, parent=os.getpid(),
                             payload=process_payload(Child.pid, parent=os.getpid())[:40])

    def popen(*_args, **_kwargs):
        garbled._check_raw_event(unreadable, etw.parse_event(unreadable))
        return Child()

    monkeypatch.setattr(etw.subprocess, "Popen", popen)
    fast_clock(monkeypatch)
    assert garbled._check_schema(None) == "schema_process_mismatch"


def test_a_rundown_of_hundreds_does_not_push_out_the_child_start(monkeypatch) -> None:
    observer = etw.EtwObserver(lambda _path: None)
    observer.state = "checking"

    def popen(*_args, **_kwargs):
        deliver(observer, raw_process(1, Child.pid, parent=os.getpid()))
        for pid in range(20_000, 20_400):
            observer._parsed(etw.parse_event(raw_process(3, pid)))
        return Child()

    monkeypatch.setattr(etw.subprocess, "Popen", popen)
    fast_clock(monkeypatch)
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
    assert api.enabled == []
    assert native.enable().status == "STARTED"
    assert api.enabled == [(etw.PROCESS_PROVIDER, 1, 0, etw.PROCESS_KEYWORDS)]
    props = etw.EVENT_TRACE_PROPERTIES.from_buffer(etw._properties())
    assert (props.BufferSize, props.MinimumBuffers, props.MaximumBuffers,
            props.FlushTimer, props.LogFileMode) == (64, 16, 64, 1, 0x02000100)


def test_failed_check_logs_only_own_dcstart_and_child_start_bytes(caplog) -> None:
    observer = etw.EtwObserver(lambda _path: None)
    observer.state = "checking"
    observer._check_children[Child.pid] = 0.0
    own = raw_process(3, os.getpid())
    other = raw_process(3, os.getpid() + 1)
    child = raw_process(1, Child.pid, parent=os.getpid())
    stranger = raw_process(1, Child.pid + 1)
    for raw in (own, other, stranger, child, own):
        observer._check_raw_event(raw, etw.parse_event(raw))
    with caplog.at_level(logging.WARNING):
        observer._log_check_failure("schema_process_mismatch")
    lines = [record.message for record in caplog.records if record.message.startswith("etw check:")]
    assert lines[0].startswith("etw check: schema_process_mismatch counts ")
    assert len(lines) == 3
    assert "process/3 v4 " in lines[1] and own.payload[:160].hex() in lines[1]
    assert "process/1 v4 " in lines[2] and child.payload[:160].hex() in lines[2]
    for unrelated in (other, stranger):
        assert unrelated.payload[:160].hex() not in " ".join(lines)
    assert not observer._raw_starts


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
