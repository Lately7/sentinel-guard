"""Observe-only private ETW session with bounded callback transfer."""

from __future__ import annotations

import ctypes
import contextlib
import json
import logging
import ntpath
import os
import queue
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter, deque
from ctypes import wintypes
from dataclasses import dataclass
from typing import Callable, Protocol

from . import procwatch

SESSION_NAME = "SentinelGuard-FileObserve-v1"
SESSION_MARKER = uuid.UUID("e3fe8f27-d3f1-4c7e-99a7-677eeeb74d01")
MAX_PAYLOAD = 512
MAX_COMMAND_LINE = 256
QUEUE_SIZE = 8192
MAX_FILE_OBJECTS = 65_536
MAX_PROCESSES = 16_384
JOIN_TTL = 10.0
FILE_RATE_LIMIT = 20_000
FILE_RATE_SECONDS = 15.0
FILE_RETRY_SECONDS = 600.0
FILE_RETRY_MAX = 3600.0
ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183
ERROR_NO_SYSTEM_RESOURCES = 1450
ERROR_WMI_INSTANCE_NOT_FOUND = 4201
IO_KEYWORDS = 0x10 | 0x04  # SYSTEM_IO_KW_FILE | SYSTEM_IO_KW_FILENAME
PROCESS_KEYWORDS = 0x01  # SYSTEM_PROCESS_KW_GENERAL
IO_PROVIDER = uuid.UUID("3d5c43e3-0f1c-4202-b817-174c0070dc79")
PROCESS_PROVIDER = uuid.UUID("151f55dc-467d-471f-83b5-5f889d46ff66")
FILE_IO_CLASS = uuid.UUID("90cbdc39-4a3e-11d1-84f4-0000f80464e3")
PROCESS_CLASS = uuid.UUID("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c")
EVENT_TRACE_CLASS = uuid.UUID("68fdd900-4a3e-11d1-84f4-0000f80464e3")
LOST_EVENT_CLASS = uuid.UUID("6a399ae0-4bc6-4de9-870b-3657f8947e7e")
SYSTEM_CONFIG_CLASS = uuid.UUID("01853a65-418f-4f36-aefc-dc0f1d2fd235")
# The system providers keep the classic MOF numbering: the operation is the
# event's opcode, and only these class versions have the layouts parsed below.
FILE_VERSIONS = (2, 3)
PROCESS_VERSIONS = (3, 4)
OP_FILE_NAME = (0, 32, 35, 36)  # name, create, delete, rundown
OP_READ, OP_WRITE = 67, 68
OP_PROCESS_START, OP_PROCESS_END = 1, 2
OP_PROCESS_DCSTART = 3


@dataclass(frozen=True)
class Capability:
    available: bool
    reason: str
    elevated: bool
    session_name: str = SESSION_NAME


@dataclass(frozen=True)
class StartResult:
    status: str
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
    truncated: bool = False
    cpu: int = -1


@dataclass(frozen=True)
class ParsedEvent:
    kind: str
    pid: int
    tid: int
    file_object: int = 0
    path: str = ""
    io_size: int = 0
    creation_time: int = 0
    image_name: str = ""
    command_line: str = ""
    parent_pid: int = 0


def _process_strings(data: bytes, version: int) -> tuple[str, str]:
    # Process_TypeGroup1 V3/V4, x64: V4 adds Flags. UserSID is a TOKEN_USER, a pointer and
    # attributes (16 bytes on x64), then the SID itself. The MOF does not show that header;
    # a real Start event from the owner's machine has it, and the SID read at 36 failed.
    offset = (32 if version == 3 else 36) + 16
    if len(data) < offset + 8 or data[offset] != 1:
        return "", ""
    sid_end = offset + 8 + 4 * data[offset + 1]
    if sid_end > len(data):
        return "", ""
    name_end = data.find(b"\0", sid_end)
    if name_end < 0 or name_end - sid_end > 260:
        return "", ""
    name = data[sid_end:name_end].decode("mbcs" if os.name == "nt" else "cp1252", "strict")
    if not name or "\\" in name or "/" in name:
        return "", ""
    command = data[name_end + 1:]
    terminator = next((i for i in range(0, len(command) - 1, 2)
                       if command[i:i + 2] == b"\0\0"), len(command))
    command = command[:min(terminator, MAX_COMMAND_LINE * 2)]
    command = command[:len(command) & ~1]
    return name, command.decode("utf-16-le", "strict")


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
        if event.provider in (IO_PROVIDER, FILE_IO_CLASS) and event.version in FILE_VERSIONS:
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
        if (event.provider in (PROCESS_PROVIDER, PROCESS_CLASS) and event.version in PROCESS_VERSIONS
                and event.opcode in (OP_PROCESS_START, OP_PROCESS_END, OP_PROCESS_DCSTART)
                and len(data) >= 16):
            # Process_TypeGroup1: UniqueProcessKey, ProcessId, ... The class has no
            # creation time; the start event's own timestamp is that time.
            pid, parent_pid = struct.unpack_from("<II", data, 8)
            image_name, command_line = _process_strings(data, event.version)
            if not image_name and len(data) != 16:
                return None
            kind = ("process_start" if event.opcode == OP_PROCESS_START else
                    "process_rundown" if event.opcode == OP_PROCESS_DCSTART else "process_stop")
            return ParsedEvent(kind,
                               pid, event.tid, creation_time=event.timestamp,
                               image_name=image_name, command_line=command_line,
                               parent_pid=parent_pid)
    except (UnicodeError, struct.error, ValueError, OverflowError, TypeError, AttributeError):
        return None
    return None


@dataclass
class Counters:
    callbacks: int = 0
    queued: int = 0
    parsed: int = 0
    queue_drops: int = 0
    truncated: int = 0
    parse_failures: int = 0
    handler_failures: int = 0
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
    callbacks_per_second: float = 0.0
    file_callbacks: int = 0
    guarded_gaps: int = 0
    query_failures: int = 0

    @property
    def gap(self) -> bool:
        # Not truncated: a clipped event is still delivered, and long command lines are common.
        return any((self.queue_drops, self.events_lost,
                    self.realtime_buffers_lost, self.log_buffers_lost, self.join_gaps,
                    self.handler_failures, self.guarded_gaps, self.query_failures))


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
                 priority: Callable[[RawEvent], bool] | None = None,
                 on_raw: Callable[[RawEvent, ParsedEvent | None], None] | None = None) -> None:
        if not 1 <= capacity <= QUEUE_SIZE:
            raise ValueError("ETW queue capacity out of range")
        self.backend, self.on_event = backend, on_event
        reserved = min(512, capacity // 16)
        self.queue: queue.Queue[RawEvent] = queue.Queue(maxsize=capacity - reserved)
        self.priority_queue: queue.Queue[RawEvent] = queue.Queue(maxsize=reserved or 1)
        self.priority = priority if reserved else None
        self.on_raw = on_raw
        self.counters = Counters()
        self.correlator = Correlator(self.counters)
        self._stop = threading.Event()
        self._consumer: threading.Thread | None = None
        self._aggregator: threading.Thread | None = None
        self.file_events = "checking"
        self._rate_start = time.monotonic()
        self._rate_count = 0
        self._over_limit_since: float | None = None
        self._guard_requested = False
        self._retry_at = 0.0
        self._retry_delay = FILE_RETRY_SECONDS
        self._stop_lock = threading.Lock()
        self._stopped = False
        self.phase: str | None = None
        self._measure_lock = threading.Lock()
        self._tallies: dict[str, Counter[str]] = {}
        self.kids: dict[int, tuple[str, float]] = {}
        self.tally_errors = 0
        self._own_pid = os.getpid()
        self._newest_timestamp = 0
        self._last_dc_time: float | None = None
        self._flush_results: deque[int] = deque(maxlen=8)
        self.flush_every = 0.0

    def callback(self, event: RawEvent) -> None:
        # No parsing, disk access, or blocking in the ETW callback.
        started = time.thread_time()
        self.counters.callbacks += 1
        if event.truncated:
            self.counters.truncated += 1
        now = time.monotonic()
        self._rate_count += 1
        elapsed = now - self._rate_start
        if elapsed >= 1.0:
            rate = self._rate_count / elapsed
            self.counters.callbacks_per_second = rate
            if rate > FILE_RATE_LIMIT:
                self._over_limit_since = self._over_limit_since or self._rate_start
                if now - self._over_limit_since >= FILE_RATE_SECONDS:
                    self._guard_requested = True
            else:
                self._over_limit_since = None
            self._rate_start, self._rate_count = now, 0
        if event.provider in (IO_PROVIDER, FILE_IO_CLASS):
            self.counters.file_callbacks += 1
        if not isinstance(event.payload, bytes) or len(event.payload) > MAX_PAYLOAD:
            # Unreadable, and never queued: a drop as well.
            self.counters.truncated += 1
            self.counters.queue_drops += 1
            self.counters.callback_cpu_s += time.thread_time() - started
            return
        if self.phase is not None:
            try:
                self._measure(event, now)
            except Exception:
                self.tally_errors += 1
        try:
            lane = self.priority_queue if self.priority and self.priority(event) else self.queue
            lane.put_nowait(RawEvent(event.provider, event.opcode, event.version,
                                      event.pid, event.tid, event.timestamp, event.payload,
                                      time.monotonic(), event.truncated, event.cpu))
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
        if hasattr(self.backend, "wait_consumer"):
            self.backend.wait_consumer = lambda: self._consumer.join(3.0)
        return result

    def enable(self) -> StartResult:
        method = getattr(self.backend, "enable", None)
        return method() if method is not None else StartResult("STARTED")

    def _measure(self, event: RawEvent, now: float) -> None:
        phase = self.phase
        if phase is None:
            return
        provider = event.provider
        if provider in (PROCESS_CLASS, PROCESS_PROVIDER):
            kind = f"p{event.opcode}"
        elif provider == EVENT_TRACE_CLASS:
            kind = f"e{event.opcode}"
        elif provider == LOST_EVENT_CLASS:
            kind = f"l{event.opcode}"
        elif provider == SYSTEM_CONFIG_CLASS:
            kind = "s"
        elif provider in (IO_PROVIDER, FILE_IO_CLASS):
            kind = "f"
        else:
            kind = "o"
        with self._measure_lock:
            tally = self._tallies.setdefault(phase, Counter())
            tally[kind] += 1
            if event.truncated:
                tally[f"trunc_{kind}"] += 1
            if kind in ("p1", "p3"):
                tally[f"{kind}@{event.cpu}"] += 1
            if event.timestamp < self._newest_timestamp:
                tally["ts_back"] += 1
                tally["ts_back_max_ms"] = max(tally["ts_back_max_ms"],
                                               (self._newest_timestamp - event.timestamp) // 10_000)
            self._newest_timestamp = max(self._newest_timestamp, event.timestamp)
            age = (time.time_ns() // 100 + 116444736000000000 - event.timestamp) / 10_000_000
            tally["age<1s" if age < 1 else "age<3s" if age < 3 else "age>=3s"] += 1
            if kind == "p3":
                if len(event.payload) >= 12 and struct.unpack_from("<I", event.payload, 8)[0] == self._own_pid:
                    tally["own_p3"] += 1
                if self._last_dc_time is not None:
                    gap_us = round((now - self._last_dc_time) * 1_000_000)
                    tally["dcgap_sum_us"] += gap_us
                    tally["dcgap_max_ms"] = max(tally["dcgap_max_ms"], gap_us // 1000)
                self._last_dc_time = now
            if kind in ("p1", "p2") and len(event.payload) >= 16:
                pid, parent = struct.unpack_from("<II", event.payload, 8)
                if parent == self._own_pid:
                    tally[f"child_{kind}"] += 1
                    if kind == "p1" and pid not in self.kids and len(self.kids) < 8:
                        self.kids[pid] = (phase, time.perf_counter())

    def measured(self) -> dict[str, dict[str, int]]:
        with self._measure_lock:
            return {phase: dict(tally) for phase, tally in self._tallies.items()}

    def flush(self) -> int:
        method = getattr(self.backend, "flush", None)
        rc = method() if method is not None else -1
        self._flush_results.append(rc)
        return rc

    def session_stats(self) -> dict[str, int]:
        method = getattr(self.backend, "stats", None)
        if method is None:
            return {}
        try:
            return method()
        except OSError as error:
            return {"qrc": error.errno if error.errno is not None else -1}

    def lifecycle(self) -> dict[str, object]:
        result = getattr(self.backend, "process_result", None)
        return {"consumer_alive": self._consumer.is_alive() if self._consumer else False,
                "process_result": result,
                "process_entered": getattr(self.backend, "process_entered", None)}

    def _aggregate(self) -> None:
        next_loss_query = time.monotonic() + 3.0
        next_guard = time.monotonic() + 0.2
        next_flush = time.monotonic() + self.flush_every if self.flush_every else 0.0
        while (not self._stop.is_set() or (self._consumer is not None and self._consumer.is_alive())
               or not self.queue.empty() or not self.priority_queue.empty()):
            now = time.monotonic()
            if not self._stop.is_set() and now >= next_guard:
                self._file_rate_guard()
                next_guard = now + 0.2
            if not self._stop.is_set() and now >= next_loss_query:
                self.poll_loss()
                next_loss_query = time.monotonic() + 3.0
            if not self._stop.is_set() and self.flush_every:
                if not next_flush:
                    next_flush = now + self.flush_every
                elif now >= next_flush:
                    self.flush()
                    next_flush = now + self.flush_every
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
            if self.on_raw is not None:
                try:
                    self.on_raw(raw, parsed)
                except Exception:
                    self.counters.handler_failures += 1
            if parsed is None:
                self.counters.parse_failures += 1
            else:
                self.counters.parsed += 1
                self.correlator.observe(parsed)
                try:
                    self.on_event(parsed)
                except Exception:
                    self.counters.handler_failures += 1

    def _file_rate_guard(self) -> None:
        now = time.monotonic()
        if self.file_events == "on" and self._guard_requested:
            self._guard_requested = False
            self._over_limit_since = None
            if self._set_file_events(False):
                self.file_events = "guarded"
                self.counters.guarded_gaps += 1
                self._retry_at = now + self._retry_delay
                self._retry_delay = min(self._retry_delay * 2, FILE_RETRY_MAX)
            else:
                self.file_events = "disable_failed"
                self.counters.guarded_gaps += 1
                self._stop.set()
                self.backend.stop()
        elif self.file_events == "guarded" and now >= self._retry_at:
            if self._set_file_events(True):
                self.file_events = "on"
                self._rate_start, self._rate_count = now, 0
                self.counters.callbacks_per_second = 0.0
            else:
                self._retry_at = now + self._retry_delay
                self._retry_delay = min(self._retry_delay * 2, FILE_RETRY_MAX)

    def _set_file_events(self, enabled: bool) -> bool:
        control = getattr(self.backend, "set_file_events", None)
        if control is None:
            return False
        try:
            return bool(control(enabled))
        except OSError:
            return False

    def after_check(self, want_files: bool) -> bool:
        if want_files:
            self.file_events = "on"
            return True
        if getattr(self.backend, "set_file_events", None) is not None and not self._set_file_events(False):
            return False
        self.file_events = "off"
        return True

    def callback_rate(self) -> float:
        return self.counters.callbacks_per_second if time.monotonic() - self._rate_start < 2.0 else 0.0

    def poll_loss(self) -> Counters:
        if self._stop.is_set():
            return self.counters
        try:
            events, realtime, logs = self.backend.loss()
            self.counters.events_lost = max(self.counters.events_lost, events)
            self.counters.realtime_buffers_lost = max(self.counters.realtime_buffers_lost, realtime)
            self.counters.log_buffers_lost = max(self.counters.log_buffers_lost, logs)
        except OSError:
            self.counters.query_failures += 1
        return self.counters

    def stop(self) -> bool:
        """True only for the call that stopped the session."""
        with self._stop_lock:
            if self._stopped:
                return False
            self._stopped = True
            self._stop.set()
        deadline = time.monotonic() + 6.0
        self.backend.stop()
        for thread in (self._consumer, self._aggregator):
            if thread:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        return True


FORWARDED = frozenset(("name", "read", "write", "process_start", "process_stop"))


def device_map() -> dict[str, str]:
    """\\Device\\HarddiskVolume3 -> C:, since file events name files by device."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    k32.QueryDosDeviceW.restype = wintypes.DWORD
    found: dict[str, str] = {}
    buffer = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if k32.QueryDosDeviceW(f"{letter}:", buffer, len(buffer)):
            found[buffer.value.lower()] = f"{letter}:"
    return found


def on_drive(path: str, devices: dict[str, str]) -> str:
    """The drive-letter form of a device path, or the path unchanged."""
    head, slash, rest = path[1:].partition("\\")
    device, slash2, tail = rest.partition("\\")
    drive = devices.get(f"\\{head}\\{device}".lower()) if path.startswith("\\") else None
    return f"{drive}\\{tail}" if drive else path


class EtwObserver:
    """Optional scan hints, gated by a bounded live layout check."""

    def __init__(self, on_process: Callable[[str], None], *,
                 on_file_event: Callable[[ParsedEvent], None] | None = None,
                 backend_factory: Callable[[uuid.UUID], Backend] = lambda guid: NativeBackend(session_guid=guid),
                 check: Callable[[Collector], str] | None = None,
                 read_guid: Callable[[], str] = lambda: "",
                 write_guid: Callable[[str], None] = lambda value: None) -> None:
        self.on_process, self.on_file_event = on_process, on_file_event
        self.backend_factory, self.check = backend_factory, check or self._check_schema
        self.read_guid, self.write_guid = read_guid, write_guid
        self.state = "off"
        self.collector: Collector | None = None
        self._checking: deque[ParsedEvent] = deque(maxlen=256)
        self._check_counts: Counter[tuple[str, int]] = Counter()
        self._check_raw: deque[RawEvent] = deque(maxlen=1)  # the service's own DCStart
        self._raw_starts: deque[RawEvent] = deque(maxlen=256)
        self._raw_start_pids: set[int] = set()
        self._check_children: dict[int, float] = {}
        self._check_event_phases: dict[int, str] = {}
        self._pass_phase: str | None = None
        self.flush_assist = False
        self.check_phase: str | None = None
        self._sleep_count = 0
        self._sleep_late = 0
        self._sleep_worst_ms = 0.0
        self._check_loss: int | None = None
        self._lock = threading.Lock()
        self._lifecycle = threading.Lock()
        self._stopping = threading.Event()
        self.exits_before_resolution = 0

    def start(self) -> None:
        try:
            self._start()
        except Exception:
            if not self._stopping.is_set():
                self.state = "startup_error"
                self._log_check_failure("startup_error")
            if self.collector is not None:
                try:
                    self.collector.stop()
                except Exception:
                    pass

    def _start(self) -> None:
        if self._stopping.is_set():
            return
        self.state = "checking"
        prior = self.read_guid()
        if prior:
            try:
                old = uuid.UUID(prior)
            except ValueError:
                self.state = "orphan_marker_invalid"
                return
            result = cleanup_orphan(old, stored_name=SESSION_NAME)
            if result.status not in ("ABSENT", "STOPPED"):
                self.state = "orphan_" + result.status.lower()
                return
        guid = uuid.uuid4()
        self.write_guid(str(guid))
        with self._lifecycle:
            if self._stopping.is_set():
                return
            collector = Collector(self.backend_factory(guid), self._parsed,
                                  priority=lambda raw: raw.provider in (PROCESS_PROVIDER, PROCESS_CLASS),
                                  on_raw=self._check_raw_event)
            collector.phase = "P"
            self.collector = collector
            result = collector.start()
        if result.status != "STARTED":
            self.state = result.status.lower() + (f"_{result.error}" if result.error else "")
            return
        if getattr(collector.backend, "enable", None) is not None:
            connected_at = time.monotonic()
            while (collector.counters.callbacks == 0 and not self._stopping.is_set()
                   and time.monotonic() - connected_at < 2.0):
                self._stopping.wait(0.05)
            path = "callback" if collector.counters.callbacks else "timeout"
            elapsed_ms = round((time.monotonic() - connected_at) * 1000)
            try:
                self._log_check("connect", path=path, ms=elapsed_ms,
                                callbacks=collector.counters.callbacks,
                                processes=self._process_count(), stats=collector.session_stats(),
                                phase_p=collector.measured().get("P", {}))
            except Exception:
                pass
            if self._stopping.is_set():
                self._stop_check(collector)
                return
            collector.phase = "W"
            self.check_phase = "W"
            enabled = collector.enable()
            if enabled.status != "STARTED":
                # A service stop in between makes the enable fail; the state stays "off".
                if not self._stopping.is_set():
                    self.state = "enable_" + enabled.status.lower() + (f"_{enabled.error}" if enabled.error else "")
                self._stop_check(collector)
                return
        else:
            collector.phase = "W"
            self.check_phase = "W"
        try:
            reason = self.check(collector)
        except (OSError, subprocess.SubprocessError, ValueError):
            reason = "schema_check_failed"
        self._check_loss = self._loss_total(collector.poll_loss())
        self._log_result(collector, reason)
        if reason or self._stopping.is_set():
            if reason and not self._stopping.is_set():
                self.state = reason
                self._log_check_failure(reason)
            self._stop_check(collector)
            return
        with self._lifecycle:
            if self._stopping.is_set():
                collector.stop()
                return
            collector.file_events = "off"
            collector.phase = None
            with self._lock:
                self.state = "on"
                self._checking.clear()
                self._check_raw.clear()
                self._raw_starts.clear()
                self._raw_start_pids.clear()
                collector.on_raw = None

    def _check_schema(self, collector: Collector | None) -> str:
        image = ntpath.basename(sys.executable).casefold()
        began = time.monotonic()
        spawned: dict[str, int] = {}
        flushed: set[int] = set()
        phase = "W"
        matched: str | None = None
        with contextlib.ExitStack() as stack:
            while not self._stopping.is_set():
                now = time.monotonic()
                with self._lock:
                    for event in self._checking:
                        if (event.pid in spawned.values() and event.parent_pid == os.getpid()
                                and event.image_name.casefold() == image):
                            seen_phase = self._check_event_phases.get(event.pid, phase)
                            if matched is None:
                                matched = seen_phase
                elapsed = now - began
                if elapsed >= 7.0:
                    break
                if "A" not in spawned:
                    self._spawn_check_child(stack, spawned, "A")
                if elapsed >= 3.0 and "B" not in spawned:
                    self._phase_end(collector, phase)
                    phase = "B"
                    if collector is not None:
                        collector.phase = phase
                    self.check_phase = phase
                    self._spawn_check_child(stack, spawned, "B")
                if elapsed >= 5.0 and phase != "F":
                    self._phase_end(collector, phase)
                    phase = "F"
                    if collector is not None:
                        collector.phase = phase
                    self.check_phase = phase
                for second in (5, 6):
                    if elapsed >= second and second not in flushed:
                        flushed.add(second)
                        if collector is not None:
                            collector.flush()
                self._check_sleep(min(began + 7, now + 0.05))
        self._phase_end(collector, phase)
        self._pass_phase = matched
        if matched in ("W", "B", "F"):
            if matched == "F":
                self.flush_assist = True
                if collector is not None:
                    collector.flush_every = 1.0
            return ""
        with self._lock:
            delivered = any(pid in self._raw_start_pids for pid in spawned.values())
        return "schema_process_mismatch" if delivered else "no_start_events"

    def _spawn_check_child(self, stack: contextlib.ExitStack, spawned: dict[str, int], label: str) -> None:
        spawn_at = time.perf_counter()
        child = stack.enter_context(subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", "import time; time.sleep(3)"],
            shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL))
        spawned[label] = child.pid
        with self._lock:
            self._check_children[child.pid] = spawn_at

    def _check_sleep(self, target: float) -> None:
        remaining = target - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        late_ms = max(0.0, (time.monotonic() - target) * 1000)
        self._sleep_count += 1
        self._sleep_late += late_ms > 50
        self._sleep_worst_ms = max(self._sleep_worst_ms, late_ms)

    @staticmethod
    def _loss_total(counters: Counters) -> int:
        return (counters.queue_drops + counters.events_lost
                + counters.realtime_buffers_lost + counters.log_buffers_lost
                + counters.handler_failures)

    def _parsed(self, event: ParsedEvent) -> None:
        with self._lock:
            state = self.state
            if state == "checking":
                # Only starts: the rundown lists every running process at once and
                # would push the child's start out of the bounded deque.
                if event.kind == "process_start" and event.parent_pid == os.getpid():
                    self._checking.append(event)
                    if self.collector is not None:
                        self._check_event_phases.setdefault(event.pid, self.collector.phase or "W")
                return
        if state != "on":
            return
        if event.kind == "process_start" and event.image_name:
            try:
                path = self._resolve_process(event.pid)
            except ProcessLookupError:
                self.exits_before_resolution += 1
                return
            except OSError:
                return
            # startswith: the event's short name may be cut to 15 characters.
            if ntpath.basename(path).casefold().startswith(event.image_name.casefold()):
                self.on_process(path)
        # Process events too: scoring needs to know when a pid starts and ends.
        if self.on_file_event is not None and event.kind in FORWARDED:
            self.on_file_event(event)

    def status(self) -> dict[str, object]:
        counters = self.collector.counters if self.collector is not None else Counters()
        lost = self._loss_total(counters)
        state = "io_guard_failed" if self.collector and self.collector.file_events == "disable_failed" else self.state
        return {"etw": state, "etw_events_parsed": counters.parsed,
                "etw_events_lost": lost, "etw_join_gaps": counters.join_gaps,
                "etw_gap": counters.gap,
                "etw_flush_assist": self.flush_assist,
                "etw_check_phase": self._pass_phase or "",
                "etw_truncated": counters.truncated,
                "etw_query_failures": counters.query_failures,
                "etw_exits_before_resolution": self.exits_before_resolution,
                "etw_file_events": "off",
                "etw_file_events_reason": "Python không theo kịp tốc độ sự kiện tệp",
                "etw_check_events_lost": self._check_loss,
                "etw_events_per_second": self.collector.callback_rate() if self.collector else 0.0,
                "etw_callback_cpu_s": counters.callback_cpu_s}

    def stop(self) -> None:
        self._stopping.set()
        checking = self.state == "checking"
        self.state = "off"
        with self._lifecycle:
            if self.collector is not None:
                if checking:
                    self.collector.phase = "S"
                if self.collector.stop() and checking:
                    try:
                        self._log_check("stop", tallies=self.collector.measured().get("S", {}),
                                        final_stats=getattr(self.collector.backend, "final_stats", None),
                                        lifecycle=self.collector.lifecycle())
                    except Exception:
                        pass

    @staticmethod
    def _resolve_process(pid: int) -> str:
        snapshot = procwatch.windows_snapshot()
        key = next((key for key in snapshot.keys if key.pid == pid), None)
        if key is None:
            if pid in snapshot.denied:
                raise OSError("process image is inaccessible")
            raise ProcessLookupError(pid)
        path, _identity = procwatch.windows_resolve(key)
        if not (len(path) >= 3 and path[0].isalpha() and path[1:3] == ":\\"
                and not path.startswith("\\\\?\\")):
            raise OSError("process image is not a drive-letter path")
        return path

    def _check_raw_event(self, raw: RawEvent, parsed: ParsedEvent | None) -> None:
        with self._lock:
            if self.state != "checking":
                return
            self._check_counts[(raw.provider.hex, raw.opcode)] += 1
            if raw.provider not in (PROCESS_PROVIDER, PROCESS_CLASS) or len(raw.payload) < 12:
                return
            if raw.opcode == OP_PROCESS_START:
                self._raw_start_pids.add(struct.unpack_from("<I", raw.payload, 8)[0])
                self._raw_starts.append(raw)
            elif (raw.opcode == OP_PROCESS_DCSTART and not self._check_raw
                  and struct.unpack_from("<I", raw.payload, 8)[0] == os.getpid()):
                self._check_raw.append(raw)

    def _log_check_failure(self, reason: str) -> None:
        try:
            with self._lock:
                counts = sorted(self._check_counts.items())
                samples = tuple(self._check_raw) + tuple(
                    raw for raw in self._raw_starts
                    if struct.unpack_from("<I", raw.payload, 8)[0] in self._check_children)[:2]
                self._raw_starts.clear()
                self._raw_start_pids.clear()
            log = logging.getLogger(__name__)
            log.warning("etw check: %s counts %s", reason,
                        ", ".join(f"{provider}/{opcode}={count}" for (provider, opcode), count in counts))
            for raw in samples:
                log.warning("etw check: process/%d v%d %s", raw.opcode, raw.version, raw.payload[:160].hex())
        except Exception:
            pass

    @staticmethod
    def _log_check(label: str, **fields: object) -> None:
        try:
            logging.getLogger(__name__).warning("etw check: %s %s", label,
                json.dumps(fields, sort_keys=True, default=lambda _value: "<unsupported>"))
        except Exception:
            pass

    @staticmethod
    def _process_count() -> int | None:
        try:
            return len(procwatch.windows_snapshot().keys)
        except Exception:
            return None

    def _phase_end(self, collector: Collector | None, phase: str) -> None:
        if collector is None:
            return
        try:
            tally = collector.measured().get(phase, {})
            self._log_check("phase " + phase, tallies=tally,
                            cpu={key: value for key, value in tally.items() if "@" in key},
                            stats=collector.session_stats(),
                            sleeps=self._sleep_count, late=self._sleep_late,
                            worst_ms=round(self._sleep_worst_ms))
        except Exception:
            pass

    def _log_result(self, collector: Collector, reason: str) -> None:
        try:
            with self._lock:
                children = {}
                for label, (pid, spawned_at) in zip(("A", "B"), self._check_children.items()):
                    child = collector.kids.get(pid)
                    children[label] = (self._check_event_phases.get(pid),
                                       round((child[1] - spawned_at) * 1000) if child else None)
            c = collector.counters
            self._log_check("result", result="interrupted" if self._stopping.is_set() else
                            reason or "pass", pass_phase=self._pass_phase, children=children,
                            flush=list(collector._flush_results), lifecycle=collector.lifecycle(),
                            queue_drops=c.queue_drops, truncated=c.truncated,
                            events_lost=c.events_lost, realtime_buffers_lost=c.realtime_buffers_lost,
                            log_buffers_lost=c.log_buffers_lost, query_failures=c.query_failures,
                            handler_failures=c.handler_failures, join_gaps=c.join_gaps,
                            guarded_gaps=c.guarded_gaps,
                            callbacks=c.callbacks, queued=c.queued, high_water=c.queue_high_water,
                            max_delivery_ms=round(c.max_delivery_ms), tally_errors=collector.tally_errors)
        except Exception:
            pass

    def _stop_check(self, collector: Collector) -> None:
        collector.phase = "S"
        if not collector.stop():
            return  # EtwObserver.stop got there first and logged it
        try:
            self._log_check("stop", tallies=collector.measured().get("S", {}),
                            final_stats=getattr(collector.backend, "final_stats", None),
                            lifecycle=collector.lifecycle())
        except Exception:
            pass


def _same_file(event_path: str, known_path: str) -> bool:
    if event_path.startswith("\\Device\\"):
        event_path = "\\\\?\\GLOBALROOT" + event_path
    return os.path.samefile(event_path, known_path)


def _same_file_safe(event_path: str, known_path: str) -> bool:
    try:
        return _same_file(event_path, known_path)
    except OSError:
        return False


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


def _control_properties(session_guid: uuid.UUID = SESSION_MARKER) -> ctypes.Array[ctypes.c_byte]:
    buf = ctypes.create_string_buffer(ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024 * 2)
    props = EVENT_TRACE_PROPERTIES.from_buffer(buf)
    props.Wnode.BufferSize = len(buf)
    props.Wnode.Guid = _guid(session_guid)
    props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    props.LogFileNameOffset = props.LoggerNameOffset + 1024 * 2
    name = (SESSION_NAME + "\0").encode("utf-16-le")
    ctypes.memmove(ctypes.addressof(buf) + props.LoggerNameOffset, name, len(name))
    return buf


def _stats(buf: ctypes.Array[ctypes.c_byte]) -> dict[str, int]:
    props = EVENT_TRACE_PROPERTIES.from_buffer(buf)
    return {name: int(getattr(props, name)) for name in (
        "BufferSize", "MinimumBuffers", "MaximumBuffers", "FlushTimer",
        "NumberOfBuffers", "FreeBuffers", "BuffersWritten", "EventsLost",
        "RealTimeBuffersLost", "LogBuffersLost")}


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
    props = _control_properties()
    code = api.ControlTraceW(ctypes.c_uint64(0), SESSION_NAME, props, 0)
    if code == ERROR_WMI_INSTANCE_NOT_FOUND:
        return StartResult("ABSENT")
    if code:
        return StartResult("UNAVAILABLE", code)
    actual = uuid.UUID(bytes_le=bytes(EVENT_TRACE_PROPERTIES.from_buffer(props).Wnode.Guid))
    if actual != expected_guid:
        return StartResult("FOREIGN_SESSION")
    props = _control_properties(expected_guid)
    code = api.ControlTraceW(ctypes.c_uint64(0), SESSION_NAME, props, 1)
    return StartResult("STOPPED" if code == 0 else "ERROR", code)


class NativeBackend:
    """Private system logger; the caller checks live schemas before using events."""

    def __init__(self, *, session_guid: uuid.UUID | None = None,
                 schema_verified: bool = False, io_keywords: int = IO_KEYWORDS,
                 process_keywords: int = PROCESS_KEYWORDS) -> None:
        self.session_guid = session_guid or uuid.uuid4()
        self.schema_verified = schema_verified
        self.io_keywords, self.process_keywords = io_keywords, process_keywords
        self.handle = ctypes.c_uint64()
        self.trace = ctypes.c_uint64(0xffffffffffffffff)
        self.owned = False
        self._callback = None
        self._logfile = None
        self.process_entered: float | None = None
        self.process_result: tuple[int, float] | None = None
        self.final_stats: dict[str, int] | None = None
        self.wait_consumer: Callable[[], None] | None = None
        self._api = ctypes.WinDLL("advapi32", use_last_error=True) if os.name == "nt" else None

    def start(self, callback: Callable[[RawEvent], None]) -> StartResult:
        if self._api is None:
            return StartResult("UNAVAILABLE")
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            return StartResult("UNAVAILABLE")
        if not self.process_keywords:
            return StartResult("UNAVAILABLE")
        props = _properties(self.session_guid)
        code = self._api.StartTraceW(ctypes.byref(self.handle), SESSION_NAME, props)
        if code:
            status = ("DENIED" if code == ERROR_ACCESS_DENIED else
                      "FOREIGN_SESSION" if code == ERROR_ALREADY_EXISTS else "UNAVAILABLE")
            return StartResult(status, code)
        self.owned = True
        try:
            factory = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)

            def receive(ptr: ctypes.POINTER(EVENT_RECORD)) -> None:
                if not ptr:
                    return
                record = ptr.contents
                length = record.UserDataLength
                if length and not record.UserData:
                    callback(RawEvent(uuid.UUID(int=0), 0, 0, 0, 0, 0, bytes(MAX_PAYLOAD + 1)))
                    return
                header = record.EventHeader
                payload = ctypes.string_at(record.UserData, min(length, MAX_PAYLOAD)) if length else b""
                callback(RawEvent(uuid.UUID(bytes_le=bytes(header.ProviderId)),
                                  header.EventDescriptor.Opcode, header.EventDescriptor.Version,
                                  header.ProcessId, header.ThreadId, header.TimeStamp, payload,
                                  truncated=length > MAX_PAYLOAD,
                                  cpu=record.BufferContext & 0xffff))

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

    def enable(self) -> StartResult:
        if not self.owned or self._api is None:
            return StartResult("ERROR")
        try:
            for provider, keywords in ((PROCESS_PROVIDER, self.process_keywords),):
                guid = _guid(provider)
                code = self._api.EnableTraceEx2(self.handle, ctypes.byref(guid), 1, 0,
                                                ctypes.c_uint64(keywords), 0, 0, None)
                if code:
                    return StartResult("DENIED" if code == ERROR_ACCESS_DENIED else "ERROR", code)
            return StartResult("STARTED")
        except (OSError, ValueError):
            return StartResult("ERROR", ctypes.get_last_error())

    def process(self) -> None:
        if self._api and self.trace.value != 0xffffffffffffffff:
            handles = (ctypes.c_uint64 * 1)(self.trace.value)
            self.process_entered = time.monotonic()
            rc = self._api.ProcessTrace(handles, 1, None, None)
            self.process_result = (rc, time.monotonic())

    def set_file_events(self, enabled: bool) -> bool:
        if not self.owned or self._api is None:
            return False
        guid = _guid(IO_PROVIDER)
        code = self._api.EnableTraceEx2(self.handle, ctypes.byref(guid), 1 if enabled else 0,
                                        0, ctypes.c_uint64(self.io_keywords if enabled else 0),
                                        0, 0, None)
        return code == 0

    def loss(self) -> tuple[int, int, int]:
        stats = self.stats()
        return stats["EventsLost"], stats["RealTimeBuffersLost"], stats["LogBuffersLost"]

    def stats(self) -> dict[str, int]:
        if not self.owned or self._api is None:
            raise OSError("trace unavailable")
        props = _control_properties(self.session_guid)
        code = self._api.ControlTraceW(self.handle, SESSION_NAME, props, 0)
        if code:
            raise OSError(code, "ControlTrace query failed")
        return _stats(props)

    def flush(self) -> int:
        if not self.owned or self._api is None:
            return -1
        return self._api.ControlTraceW(self.handle, SESSION_NAME,
                                       _control_properties(self.session_guid), 3)

    def stop(self) -> None:
        if self._api is None:
            return
        props = _control_properties(self.session_guid)
        query = self._api.ControlTraceW(self.handle, SESSION_NAME, props, 0) if self.owned else 1
        same_guid = (query == 0 and
                     uuid.UUID(bytes_le=bytes(EVENT_TRACE_PROPERTIES.from_buffer(props).Wnode.Guid))
                     == self.session_guid)
        if self.owned and same_guid:
            for provider in (PROCESS_PROVIDER,):
                guid = _guid(provider)
                self._api.EnableTraceEx2(self.handle, ctypes.byref(guid), 0, 0, 0, 0, 0, None)
            props = _control_properties(self.session_guid)
            stop_rc = self._api.ControlTraceW(self.handle, SESSION_NAME, props, 1)
            if self.final_stats is None:
                self.final_stats = {**_stats(props), "stop_rc": stop_rc}
        self.owned = False
        if self.wait_consumer is not None:
            self.wait_consumer()
        if self.trace.value != 0xffffffffffffffff:
            self._api.CloseTrace(self.trace)
            self.trace = ctypes.c_uint64(0xffffffffffffffff)
