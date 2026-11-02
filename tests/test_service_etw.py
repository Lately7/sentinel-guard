import struct
import uuid

from sentinel.service import etw


def raw(provider, opcode, payload, version=3, timestamp=0):
    return etw.RawEvent(provider, opcode, version, 99, 5, timestamp, payload)


def write_payload(file_object=42, size=4096):
    return struct.pack("<QQQQIII", 0, 0, file_object, 0, 5, size, 0)


def test_pure_versioned_parsing_rejects_hostile_bytes():
    name = raw(etw.IO_PROVIDER, 35, struct.pack("<Q", 42) + "C:\\a.txt\0".encode("utf-16-le"))
    assert etw.parse_event(name).file_object == 42
    assert etw.parse_event(raw(etw.IO_PROVIDER, 68, b"\0" * 8)) is None
    wrote = etw.parse_event(raw(etw.IO_PROVIDER, 68, write_payload()))
    assert (wrote.kind, wrote.file_object, wrote.io_size) == ("write", 42, 4096)
    assert etw.parse_event(raw(etw.IO_PROVIDER, 35, b"\0" * 8 + b"\xff")) is None
    assert etw.parse_event(raw(etw.IO_PROVIDER, 35, name.payload, version=7)) is None
    assert etw.parse_event(raw(etw.IO_PROVIDER, 35, None)) is None
    process = etw.parse_event(raw(etw.PROCESS_PROVIDER, 1, struct.pack("<QII", 0xFFFF, 123, 7), version=4, timestamp=456))
    assert process.pid == 123 and process.creation_time == 456  # payload PID, not the header's 99


def test_bounded_callback_gap_and_fake_backend():
    class Fake:
        def start(self, callback):
            self.callback = callback
            return etw.StartResult("STARTED")

        def process(self):
            return None

        def loss(self):
            return (1, 0, 0)

        def stop(self):
            self.stopped = True

    fake = Fake()
    collector = etw.Collector(fake, lambda _event: None, capacity=1)
    assert collector.start().status == "STARTED"
    fake.callback(raw(etw.IO_PROVIDER, 68, b"x" * (etw.MAX_PAYLOAD + 1)))
    assert collector.counters.truncated == 1
    assert collector.poll_loss().gap
    collector.stop()
    assert fake.stopped


def test_full_reserved_canary_lane_is_visible_loss():
    collector = etw.Collector(None, lambda _event: None, capacity=16, priority=lambda _event: True)
    event = raw(etw.IO_PROVIDER, 68, b"x")
    collector.callback(event)
    collector.callback(event)
    assert collector.counters.queue_drops == 1
    assert collector.counters.gap


def test_private_session_properties_and_platform_probe():
    props = etw.EVENT_TRACE_PROPERTIES.from_buffer(etw._properties())
    assert props.FlushTimer == 1
    assert props.LogFileMode & 0x02000000
    assert etw.capability_probe().session_name == etw.SESSION_NAME


def test_correlation_remains_weak_until_live_handle_check():
    counters = etw.Counters()
    joins = etw.Correlator(counters, clock=lambda: 10.0)
    joins.observe(etw.ParsedEvent("process_start", 99, 0, creation_time=123))
    joins.observe(etw.ParsedEvent("name", 99, 0, file_object=42, path="C:\\a.txt"))
    result = joins.observe(etw.ParsedEvent("write", 99, 0, file_object=42))
    assert (result.path, result.creation_time, result.strong) == ("C:\\a.txt", 123, False)
    assert joins.observe(etw.ParsedEvent("write", 99, 0, file_object=43)) is None
    assert counters.join_gaps == 1 and counters.gap


def test_orphan_cleanup_never_stops_unknown_guid():
    class Fake:
        calls = []

        def ControlTraceW(self, handle, name, props, command):
            self.calls.append(command)
            return 0

    fake = Fake()
    assert etw.cleanup_orphan(uuid.uuid4(), stored_name="other", api=fake).status == "FOREIGN_SESSION"
    assert fake.calls == []
    assert etw.cleanup_orphan(uuid.uuid4(), stored_name=etw.SESSION_NAME, api=fake).status == "FOREIGN_SESSION"
    assert fake.calls == [0]


def test_real_start_access_denial_is_typed_without_touching_session():
    class Denied:
        def StartTraceW(self, handle, name, props):
            return etw.ERROR_ACCESS_DENIED

    backend = etw.NativeBackend(schema_verified=True, io_keywords=1, process_keywords=1)
    backend._api = Denied()
    assert backend.start(lambda _event: None).status == "DENIED"
    assert not backend.owned
