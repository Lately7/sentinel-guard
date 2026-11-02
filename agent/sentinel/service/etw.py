"""Observe-only private ETW session with bounded callback transfer (R14 milestones 1 to 3).

Dormant until proven: NativeBackend refuses to start before the event layouts
were checked on the machine it runs on, because a guessed layout would attribute
writes to the wrong file. Starting a session also needs elevation, so everything
here is tested on canned bytes; nothing suspends any process.
"""

from __future__ import annotations

import ctypes
import os
import queue
import struct
import threading
import time
import uuid
from ctypes import wintypes
from dataclasses import dataclass
from typing import Callable, Protocol

SESSION_NAME = "SentinelGuard-FileObserve-v1"
SESSION_MARKER = uuid.UUID("e3fe8f27-d3f1-4c7e-99a7-677eeeb74d01")
MAX_PAYLOAD = 512
QUEUE_SIZE = 8192
MAX_FILE_OBJECTS = 65_536
MAX_PROCESSES = 16_384
JOIN_TTL = 10.0
ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183
ERROR_NO_SYSTEM_RESOURCES = 1450
IO_PROVIDER = uuid.UUID("3d5c43e3-0f1c-4202-b817-174c0070dc79")
PROCESS_PROVIDER = uuid.UUID("151f55dc-467d-471f-83b5-5f889d46ff66")
# The system providers keep the classic MOF numbering: the operation is the
# event's opcode, and only these class versions have the layouts parsed below.
FILE_VERSIONS = (2, 3)
PROCESS_VERSIONS = (3, 4)
OP_FILE_NAME = (0, 32, 35, 36)  # name, create, delete, rundown
OP_READ, OP_WRITE = 67, 68
OP_PROCESS_START, OP_PROCESS_END = 1, 2


@dataclass(frozen=True)
class Capability:
    available: bool
    reason: str
    elevated: bool
    session_name: str = SESSION_NAME


@dataclass(frozen=True)
class StartResult:
    status: str  # STARTED | DENIED | UNAVAILABLE | FOREIGN_SESSION | ERROR
    error: int = 0


@dataclass(frozen=True)
class RawEvent:
    provider: uuid.UUID
    opcode: int
    version: int
    pid: int
    tid: int
    timestamp: int
    payload: bytes
    received_at: float = 0.0


@dataclass(frozen=True)
class ParsedEvent:
    kind: str
    pid: int
    tid: int
    file_object: int = 0
    path: str = ""
    io_size: int = 0
    creation_time: int = 0


@dataclass(frozen=True)
class Correlation:
    path: str
    pid: int
    creation_time: int
    strong: bool = False  # live process-handle recheck is required by R14.


def parse_event(event: RawEvent) -> ParsedEvent | None:
    """Only verified classic layouts; unknown versions never imply attribution."""
    try:
        data = event.payload
        if event.provider == IO_PROVIDER and event.version in FILE_VERSIONS:
            # FileIo_Name: FileObject, then the UTF-16 path.
            if event.opcode in OP_FILE_NAME and len(data) >= 10:
                file_object = struct.unpack_from("<Q", data)[0]
                path = data[8:].decode("utf-16-le", "strict").split("\0", 1)[0]
                if path and len(path) <= 260:
                    return ParsedEvent("name", event.pid, event.tid, file_object, path)
            # FileIo_ReadWrite: Offset, IrpPtr, FileObject, FileKey, TTID, IoSize, IoFlags.
            if event.opcode in (OP_READ, OP_WRITE) and len(data) >= 44:
                file_object = struct.unpack_from("<Q", data, 16)[0]
                io_size = struct.unpack_from("<I", data, 36)[0]
                return ParsedEvent("write" if event.opcode == OP_WRITE else "read",
                                   event.pid, event.tid, file_object, io_size=io_size)
        if (event.provider == PROCESS_PROVIDER and event.version in PROCESS_VERSIONS
                and event.opcode in (OP_PROCESS_START, OP_PROCESS_END) and len(data) >= 16):
            # Process_TypeGroup1: UniqueProcessKey, ProcessId, ... The class has no
            # creation time; the start event's own timestamp is that time.
            pid = struct.unpack_from("<I", data, 8)[0]
            return ParsedEvent("process_start" if event.opcode == OP_PROCESS_START else "process_stop",
                               pid, event.tid, creation_time=event.timestamp)
    except (UnicodeError, struct.error, ValueError, OverflowError, TypeError, AttributeError):
        return None
    return None


@dataclass
class Counters:
    callbacks: int = 0
    queued: int = 0
    queue_drops: int = 0
    truncated: int = 0
    parse_failures: int = 0
    unmatched_names: int = 0
    unmatched_pids: int = 0
    join_gaps: int = 0
    evicted: int = 0
    events_lost: int = 0
    realtime_buffers_lost: int = 0
    log_buffers_lost: int = 0
    queue_high_water: int = 0
    max_delivery_ms: float = 0.0
    callback_cpu_s: float = 0.0

    @property
    def gap(self) -> bool:
        return any((self.queue_drops, self.truncated, self.events_lost,
                    self.realtime_buffers_lost, self.log_buffers_lost, self.join_gaps))


class Correlator:
    def __init__(self, counters: Counters, clock: Callable[[], float] = time.monotonic) -> None:
        self.counters, self.clock = counters, clock
        self.names: dict[int, tuple[str, float]] = {}
        self.processes: dict[int, int] = {}

    def observe(self, event: ParsedEvent) -> Correlation | None:
        now = self.clock()
        if event.kind == "process_start":
            if event.pid not in self.processes and len(self.processes) >= MAX_PROCESSES:
                self.counters.join_gaps += 1
                return None
            self.processes[event.pid] = event.creation_time
        elif event.kind == "process_stop":
            self.processes.pop(event.pid, None)
        elif event.kind == "name":
            if event.file_object not in self.names and len(self.names) >= MAX_FILE_OBJECTS:
                expired = [key for key, (_, seen) in self.names.items() if now - seen > JOIN_TTL]
                for key in expired:
                    del self.names[key]
                self.counters.evicted += len(expired)
                self.counters.join_gaps += len(expired)
                if len(self.names) >= MAX_FILE_OBJECTS:
                    self.counters.join_gaps += 1
                    return None
            self.names[event.file_object] = (event.path, now)
        elif event.kind == "write":
            name = self.names.get(event.file_object)
            if not name or now - name[1] > JOIN_TTL:
                self.counters.unmatched_names += 1
                self.counters.join_gaps += 1
                return None
            creation = self.processes.get(event.pid)
            if creation is None:
                self.counters.unmatched_pids += 1
                self.counters.join_gaps += 1
                return None
            return Correlation(name[0], event.pid, creation)
        return None


class Backend(Protocol):
    def start(self, callback: Callable[[RawEvent], None]) -> StartResult: ...
    def process(self) -> None: ...
    def loss(self) -> tuple[int, int, int]: ...
    def stop(self) -> None: ...


class Collector:
    def __init__(self, backend: Backend, on_event: Callable[[ParsedEvent], None],
                 *, capacity: int = QUEUE_SIZE,
                 priority: Callable[[RawEvent], bool] | None = None) -> None:
        if not 1 <= capacity <= QUEUE_SIZE:
            raise ValueError("ETW queue capacity out of range")
        self.backend, self.on_event = backend, on_event
        reserved = min(512, capacity // 16)
        self.queue: queue.Queue[RawEvent] = queue.Queue(maxsize=capacity - reserved)
        self.priority_queue: queue.Queue[RawEvent] = queue.Queue(maxsize=reserved or 1)
        self.priority = priority if reserved else None
        self.counters = Counters()
        self.correlator = Correlator(self.counters)
        self._stop = threading.Event()
        self._consumer: threading.Thread | None = None
        self._aggregator: threading.Thread | None = None

    def callback(self, event: RawEvent) -> None:
        # No parsing, disk access, or blocking in the ETW callback.
        started = time.thread_time()
        self.counters.callbacks += 1
        if not isinstance(event.payload, bytes) or len(event.payload) > MAX_PAYLOAD:
            self.counters.truncated += 1
            self.counters.callback_cpu_s += time.thread_time() - started
            return
        try:
            lane = self.priority_queue if self.priority and self.priority(event) else self.queue
            lane.put_nowait(RawEvent(event.provider, event.opcode, event.version,
                                      event.pid, event.tid, event.timestamp, event.payload,
                                      time.monotonic()))
            self.counters.queued += 1
            self.counters.queue_high_water = max(self.counters.queue_high_water,
                self.queue.qsize() + self.priority_queue.qsize())
        except Exception:
            self.counters.queue_drops += 1
        finally:
            self.counters.callback_cpu_s += time.thread_time() - started

    def start(self) -> StartResult:
        result = self.backend.start(self.callback)
        if result.status != "STARTED":
            return result
        self._aggregator = threading.Thread(target=self._aggregate, daemon=True)
        self._consumer = threading.Thread(target=self.backend.process, daemon=True)
        self._aggregator.start()
        self._consumer.start()
        return result

    def _aggregate(self) -> None:
        next_loss_query = time.monotonic() + 3.0
        while not self._stop.is_set() or not self.queue.empty() or not self.priority_queue.empty():
            if time.monotonic() >= next_loss_query:
                self.poll_loss()
                next_loss_query = time.monotonic() + 3.0
            try:
                try:
                    raw = self.priority_queue.get_nowait()
                except queue.Empty:
                    raw = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if raw.received_at:
                self.counters.max_delivery_ms = max(self.counters.max_delivery_ms,
                    (time.monotonic() - raw.received_at) * 1000)
            parsed = parse_event(raw)
            if parsed is None:
                self.counters.parse_failures += 1
            else:
                self.correlator.observe(parsed)
                try:
                    self.on_event(parsed)
                except Exception:
                    self.counters.parse_failures += 1

    def poll_loss(self) -> Counters:
        try:
            events, realtime, logs = self.backend.loss()
            self.counters.events_lost = max(self.counters.events_lost, events)
            self.counters.realtime_buffers_lost = max(self.counters.realtime_buffers_lost, realtime)
            self.counters.log_buffers_lost = max(self.counters.log_buffers_lost, logs)
        except OSError:
            self.counters.events_lost += 1
        return self.counters

    def stop(self) -> None:
        self._stop.set()
        self.backend.stop()
        for thread in (self._consumer, self._aggregator):
            if thread:
                thread.join(timeout=5)


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


def _guid(value: uuid.UUID) -> GUID:
    return GUID.from_buffer_copy(value.bytes_le)


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", wintypes.ULONG), ("ProviderId", wintypes.ULONG),
                ("HistoricalContext", ctypes.c_uint64), ("TimeStamp", ctypes.c_int64),
                ("Guid", GUID), ("ClientContext", wintypes.ULONG), ("Flags", wintypes.ULONG)]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", wintypes.ULONG),
                ("MinimumBuffers", wintypes.ULONG), ("MaximumBuffers", wintypes.ULONG),
                ("MaximumFileSize", wintypes.ULONG), ("LogFileMode", wintypes.ULONG),
                ("FlushTimer", wintypes.ULONG), ("EnableFlags", wintypes.ULONG),
                ("AgeLimit", ctypes.c_long), ("NumberOfBuffers", wintypes.ULONG),
                ("FreeBuffers", wintypes.ULONG), ("EventsLost", wintypes.ULONG),
                ("BuffersWritten", wintypes.ULONG), ("LogBuffersLost", wintypes.ULONG),
                ("RealTimeBuffersLost", wintypes.ULONG), ("LoggerThreadId", ctypes.c_void_p),
                ("LogFileNameOffset", wintypes.ULONG), ("LoggerNameOffset", wintypes.ULONG)]


class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("Id", wintypes.WORD), ("Version", ctypes.c_ubyte), ("Channel", ctypes.c_ubyte),
                ("Level", ctypes.c_ubyte), ("Opcode", ctypes.c_ubyte), ("Task", wintypes.WORD),
                ("Keyword", ctypes.c_uint64)]


class EVENT_HEADER(ctypes.Structure):
    _fields_ = [("Size", wintypes.WORD), ("HeaderType", wintypes.WORD), ("Flags", wintypes.WORD),
                ("EventProperty", wintypes.WORD), ("ThreadId", wintypes.DWORD),
                ("ProcessId", wintypes.DWORD), ("TimeStamp", ctypes.c_int64),
                ("ProviderId", GUID), ("EventDescriptor", EVENT_DESCRIPTOR),
                ("ProcessorTime", ctypes.c_uint64), ("ActivityId", GUID)]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [("EventHeader", EVENT_HEADER), ("BufferContext", wintypes.DWORD),
                ("ExtendedDataCount", wintypes.WORD), ("UserDataLength", wintypes.WORD),
                ("ExtendedData", ctypes.c_void_p), ("UserData", ctypes.c_void_p),
                ("UserContext", ctypes.c_void_p)]


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [("LogFileName", wintypes.LPWSTR), ("LoggerName", wintypes.LPWSTR),
                ("CurrentTime", ctypes.c_int64), ("BuffersRead", wintypes.ULONG),
                ("ProcessTraceMode", wintypes.ULONG), ("CurrentEvent", ctypes.c_byte * 88),
                ("LogfileHeader", ctypes.c_byte * 280), ("BufferCallback", ctypes.c_void_p),
                ("BufferSize", wintypes.ULONG), ("Filled", wintypes.ULONG),
                ("EventsLost", wintypes.ULONG), ("EventRecordCallback", ctypes.c_void_p),
                ("IsKernelTrace", wintypes.ULONG), ("Context", ctypes.c_void_p)]


def _properties(session_guid: uuid.UUID = SESSION_MARKER) -> ctypes.Array[ctypes.c_byte]:
    name = (SESSION_NAME + "\0").encode("utf-16-le")
    buf = ctypes.create_string_buffer(ctypes.sizeof(EVENT_TRACE_PROPERTIES) + len(name) + 2)
    props = EVENT_TRACE_PROPERTIES.from_buffer(buf)
    props.Wnode.BufferSize = len(buf)
    props.Wnode.Guid = _guid(session_guid)
    props.Wnode.Flags = 0x00020000
    props.Wnode.ClientContext = 1
    props.BufferSize = 64
    props.MinimumBuffers = 16
    props.MaximumBuffers = 64
    props.FlushTimer = 1
    props.LogFileMode = 0x00000100 | 0x02000000
    props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    ctypes.memmove(ctypes.addressof(buf) + props.LoggerNameOffset, name, len(name))
    return buf


def capability_probe() -> Capability:
    if os.name != "nt":
        return Capability(False, "non_windows", False)
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        return Capability(False, "unsupported_arch", False)
    try:
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        elevated = bool(shell32.IsUserAnAdmin())
        available = all(hasattr(adv, name) for name in
                        ("StartTraceW", "EnableTraceEx2", "OpenTraceW", "ProcessTrace", "ControlTraceW"))
        reason = "api_missing" if not available else "ready" if elevated else "elevation_required"
        return Capability(available and elevated, reason, elevated)
    except OSError:
        return Capability(False, "api_missing", False)


def cleanup_orphan(expected_guid: uuid.UUID, *, stored_name: str,
                   api: object | None = None) -> StartResult:
    """Caller supplies the GUID from its protected service state; no name-only cleanup."""
    if stored_name != SESSION_NAME or expected_guid.int == 0:
        return StartResult("FOREIGN_SESSION")
    if api is None:
        if os.name != "nt":
            return StartResult("UNAVAILABLE")
        api = ctypes.WinDLL("advapi32", use_last_error=True)
    props = _properties()
    code = api.ControlTraceW(ctypes.c_uint64(0), SESSION_NAME, props, 0)
    if code:
        return StartResult("UNAVAILABLE", code)
    actual = uuid.UUID(bytes_le=bytes(EVENT_TRACE_PROPERTIES.from_buffer(props).Wnode.Guid))
    if actual != expected_guid:
        return StartResult("FOREIGN_SESSION")
    code = api.ControlTraceW(ctypes.c_uint64(0), SESSION_NAME, props, 1)
    return StartResult("STOPPED" if code == 0 else "ERROR", code)


class NativeBackend:
    """Private system logger. Live schemas must be checked on the owner build."""

    def __init__(self, *, session_guid: uuid.UUID | None = None,
                 schema_verified: bool = False, io_keywords: int = 0,
                 process_keywords: int = 0) -> None:
        self.session_guid = session_guid or uuid.uuid4()
        self.schema_verified = schema_verified
        self.io_keywords, self.process_keywords = io_keywords, process_keywords
        self.handle = ctypes.c_uint64()
        self.trace = ctypes.c_uint64(0xffffffffffffffff)
        self.owned = False
        self._callback = None
        self._logfile = None
        self._api = ctypes.WinDLL("advapi32", use_last_error=True) if os.name == "nt" else None

    def start(self, callback: Callable[[RawEvent], None]) -> StartResult:
        if self._api is None:
            return StartResult("UNAVAILABLE")
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            return StartResult("UNAVAILABLE")
        if not self.schema_verified or not self.io_keywords or not self.process_keywords:
            return StartResult("SCHEMA_UNVERIFIED")
        props = _properties(self.session_guid)
        code = self._api.StartTraceW(ctypes.byref(self.handle), SESSION_NAME, props)
        if code:
            status = ("DENIED" if code == ERROR_ACCESS_DENIED else
                      "FOREIGN_SESSION" if code == ERROR_ALREADY_EXISTS else "UNAVAILABLE")
            return StartResult(status, code)
        self.owned = True
        try:
            for provider, keywords in ((IO_PROVIDER, self.io_keywords),
                                       (PROCESS_PROVIDER, self.process_keywords)):
                guid = _guid(provider)
                code = self._api.EnableTraceEx2(self.handle, ctypes.byref(guid), 1, 0,
                                                ctypes.c_uint64(keywords), 0, 0, None)
                if code:
                    self.stop()
                    return StartResult("DENIED" if code == ERROR_ACCESS_DENIED else "ERROR", code)
            factory = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)

            def receive(ptr: ctypes.POINTER(EVENT_RECORD)) -> None:
                if not ptr:
                    return
                record = ptr.contents
                length = record.UserDataLength
                if length > MAX_PAYLOAD or (length and not record.UserData):
                    callback(RawEvent(uuid.UUID(int=0), 0, 0, 0, 0, 0, bytes(MAX_PAYLOAD + 1)))
                    return
                header = record.EventHeader
                payload = ctypes.string_at(record.UserData, length) if length else b""
                callback(RawEvent(uuid.UUID(bytes_le=bytes(header.ProviderId)),
                                  header.EventDescriptor.Opcode, header.EventDescriptor.Version,
                                  header.ProcessId, header.ThreadId, header.TimeStamp, payload))

            self._callback = factory(None, ctypes.POINTER(EVENT_RECORD))(receive)
            self._logfile = EVENT_TRACE_LOGFILEW()
            self._logfile.LoggerName = SESSION_NAME
            self._logfile.ProcessTraceMode = 0x00000100 | 0x10000000
            self._logfile.EventRecordCallback = ctypes.cast(self._callback, ctypes.c_void_p)
            self._api.OpenTraceW.restype = ctypes.c_uint64
            self.trace = ctypes.c_uint64(self._api.OpenTraceW(ctypes.byref(self._logfile)))
            if self.trace.value == 0xffffffffffffffff:
                self.stop()
                return StartResult("ERROR", ctypes.get_last_error())
            return StartResult("STARTED")
        except (OSError, ValueError):
            self.stop()
            return StartResult("ERROR", ctypes.get_last_error())

    def process(self) -> None:
        if self._api and self.trace.value != 0xffffffffffffffff:
            handles = (ctypes.c_uint64 * 1)(self.trace.value)
            self._api.ProcessTrace(handles, 1, None, None)

    def loss(self) -> tuple[int, int, int]:
        if not self.owned or self._api is None:
            raise OSError("trace unavailable")
        props = _properties(self.session_guid)
        code = self._api.ControlTraceW(self.handle, SESSION_NAME, props, 0)
        if code:
            raise OSError(code, "ControlTrace query failed")
        p = EVENT_TRACE_PROPERTIES.from_buffer(props)
        return p.EventsLost, p.RealTimeBuffersLost, p.LogBuffersLost

    def stop(self) -> None:
        if self._api is None:
            return
        props = _properties(self.session_guid)
        query = self._api.ControlTraceW(self.handle, SESSION_NAME, props, 0) if self.owned else 1
        same_guid = (query == 0 and
                     uuid.UUID(bytes_le=bytes(EVENT_TRACE_PROPERTIES.from_buffer(props).Wnode.Guid))
                     == self.session_guid)
        if self.owned and same_guid:
            for provider in (IO_PROVIDER, PROCESS_PROVIDER):
                guid = _guid(provider)
                self._api.EnableTraceEx2(self.handle, ctypes.byref(guid), 2, 0, 0, 0, 0, None)
            self._api.ControlTraceW(self.handle, SESSION_NAME, props, 1)
        self.owned = False
        if self.trace.value != 0xffffffffffffffff:
            self._api.CloseTrace(self.trace)
            self.trace = ctypes.c_uint64(0xffffffffffffffff)
