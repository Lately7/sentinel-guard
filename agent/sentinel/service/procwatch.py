"""Sampled process observation (A5, R13b P6).

A snapshot every 500 ms turns new processes into scan hints. It is not
prevention: without a driver a program is seen after it started, and one that
lives for less than a sample is not seen at all. The report says so in numbers.
"""

from __future__ import annotations

import ctypes
import os
import time
from collections import Counter, deque
from collections.abc import Callable, Iterable
from ctypes import wintypes
from dataclasses import dataclass, field

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
# The idle pseudo-process and the kernel have no image file to look at.
NO_IMAGE_PIDS = (0, 4)


@dataclass(frozen=True)
class ProcessKey:
    pid: int
    creation_time: int


@dataclass(frozen=True)
class ProcessTarget:
    key: ProcessKey
    path: str
    identity: tuple[int, int]


@dataclass(frozen=True)
class SnapshotResult:
    keys: tuple[ProcessKey, ...]
    denied: tuple[int, ...] = ()
    vanished: int = 0


@dataclass
class ObservationReport:
    process_observation: str = "sampled"
    poll_duration: float = 0.0
    failed_polls: int = 0
    inaccessible_images: int = 0
    exits_before_resolution: int = 0
    largest_gap: float = 0.0
    slept_seconds: float = 0.0
    queue_saturation: int = 0
    late_polls: int = 0
    gaps: Counter[str] = field(default_factory=Counter)


Snapshot = Callable[[], Iterable[ProcessKey] | SnapshotResult]
Resolver = Callable[[ProcessKey], tuple[str, tuple[int, int]]]


class ProcessWatcher:
    def __init__(self, snapshot: Snapshot, resolve: Resolver, *, interval: float = 0.5,
                 capacity: int = 1024, max_snapshot: int = 65536,
                 clock: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] | None = None,
                 awake_clock: Callable[[], float] | None = None) -> None:
        if interval <= 0 or capacity <= 0 or max_snapshot <= 0:
            raise ValueError("bounds")
        self.snapshot, self.resolve = snapshot, resolve
        self.interval, self.capacity, self.max_snapshot, self.clock = interval, capacity, max_snapshot, clock
        self.wall_clock = wall_clock or (_elapsed_seconds if clock is time.monotonic else clock)
        self.awake_clock = awake_clock or (_unbiased_seconds if clock is time.monotonic else clock)
        self.queue: deque[ProcessTarget] = deque()
        self.report = ObservationReport()
        self._seen: set[ProcessKey] = set()
        self._denied: set[int] = set()
        self._last_wall: float | None = None
        self._last_awake: float | None = None
        self._first_wall: float | None = None
        self._first_awake: float | None = None

    def _note(self, reason: str) -> None:
        self.report.gaps[reason] += 1

    def _take(self) -> set[ProcessKey] | None:
        try:
            snap = self.snapshot()
            denied: tuple[int, ...] = ()
            keys: Iterable[ProcessKey] = snap
            if isinstance(snap, SnapshotResult):
                keys, denied = snap.keys, snap.denied
                self.report.exits_before_resolution += snap.vanished
                if snap.vanished:
                    self._note("exited_before_resolution")
            observed: set[ProcessKey] = set()
            for key in keys:
                if len(observed) >= self.max_snapshot:
                    self._note("snapshot_limit")
                    break
                observed.add(key)
        except OSError:
            self.report.failed_polls += 1
            self._note("snapshot_failed")
            return None
        # Counted once per process: the same protected process fails every sample.
        fresh = set(denied) - self._denied
        self.report.inaccessible_images += len(fresh)
        if fresh:
            self._note("inaccessible_image")
        self._denied = set(denied)
        return observed

    def poll(self) -> tuple[ProcessTarget, ...]:
        start = self.clock()
        observed = self._take()
        if observed is None:
            self.report.poll_duration = self.clock() - start
            return ()
        found: list[ProcessTarget] = []
        handled: set[ProcessKey] = set()
        for key in sorted(observed - self._seen, key=lambda k: (k.pid, k.creation_time)):
            try:
                path, identity = self.resolve(key)
            except ProcessLookupError:
                self.report.exits_before_resolution += 1
                self._note("exited_before_resolution")
                continue
            except OSError:
                self.report.inaccessible_images += 1
                self._note("inaccessible_image")
                handled.add(key)  # a retry each sample would count one failure forever
                continue
            if len(self.queue) >= self.capacity:
                self.report.queue_saturation += 1
                self._note("queue_saturated")
                continue  # stays new, so it is offered again next sample
            target = ProcessTarget(key, path, identity)
            self.queue.append(target)
            found.append(target)
            handled.add(key)
        # Keyed with the creation time: a reused pid is a new process.
        self._seen = (self._seen & observed) | handled
        end = self.clock()
        self.report.poll_duration = end - start
        wall = self.wall_clock()
        awake = self.awake_clock()
        if self._last_wall is not None and self._last_awake is not None:
            gap = max(0.0, awake - self._last_awake)
            # Unbiased interrupt time excludes sleep, so largest_gap measures awake stalls.
            self.report.largest_gap = max(self.report.largest_gap, gap)
            assert self._first_wall is not None and self._first_awake is not None
            self.report.slept_seconds = max(self.report.slept_seconds,
                                            (wall - self._first_wall) - (awake - self._first_awake))
            if gap > self.interval * 2:
                self.report.late_polls += 1
                self._note("late_poll")
        if self.report.poll_duration > self.interval:
            self.report.late_polls += 1
            self._note("slow_poll")
        if self._first_wall is None:
            self._first_wall, self._first_awake = wall, awake
        self._last_wall = wall
        self._last_awake = awake
        return tuple(found)

    def pop(self) -> ProcessTarget | None:
        return self.queue.popleft() if self.queue else None


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]


if os.name == "nt":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.GetTickCount64.argtypes = []
    _k32.GetTickCount64.restype = ctypes.c_ulonglong
    _k32.QueryUnbiasedInterruptTime.argtypes = [ctypes.POINTER(ctypes.c_ulonglong)]
    _k32.QueryUnbiasedInterruptTime.restype = wintypes.BOOL
    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    _k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                ctypes.POINTER(wintypes.DWORD)]


def _elapsed_seconds() -> float:
    if os.name != "nt":
        return time.monotonic()
    return _k32.GetTickCount64() / 1000


def _unbiased_seconds() -> float:
    if os.name != "nt":
        return time.monotonic()
    ticks = ctypes.c_ulonglong()
    if not _k32.QueryUnbiasedInterruptTime(ctypes.byref(ticks)):
        raise ctypes.WinError(ctypes.get_last_error())
    return ticks.value / 10_000_000


def _creation_time(process: int) -> int | None:
    created, exited, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
    if not _k32.GetProcessTimes(process, ctypes.byref(created), ctypes.byref(exited),
                                ctypes.byref(kernel_time), ctypes.byref(user_time)):
        return None
    return (created.dwHighDateTime << 32) | created.dwLowDateTime


def windows_snapshot() -> SnapshotResult:
    if os.name != "nt":
        raise OSError("Windows only")
    handle = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    keys: list[ProcessKey] = []
    denied: list[int] = []
    vanished = 0
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        more = _k32.Process32FirstW(handle, ctypes.byref(entry))
        if not more:
            raise ctypes.WinError(ctypes.get_last_error())
        while more:
            pid = int(entry.th32ProcessID)
            if pid not in NO_IMAGE_PIDS:
                process = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if process:
                    try:
                        stamp = _creation_time(process)
                        if stamp is None:
                            denied.append(pid)
                        else:
                            keys.append(ProcessKey(pid, stamp))
                    finally:
                        _k32.CloseHandle(process)
                elif ctypes.get_last_error() == ERROR_INVALID_PARAMETER:
                    vanished += 1
                else:
                    denied.append(pid)
            more = _k32.Process32NextW(handle, ctypes.byref(entry))
    finally:
        _k32.CloseHandle(handle)
    return SnapshotResult(tuple(keys), tuple(denied), vanished)


def windows_resolve(key: ProcessKey) -> tuple[str, tuple[int, int]]:
    if os.name != "nt":
        raise OSError("Windows only")
    process = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, key.pid)
    if not process:
        code = ctypes.get_last_error()
        if code == ERROR_INVALID_PARAMETER:
            raise ProcessLookupError(key.pid)
        raise ctypes.WinError(code)
    try:
        if _creation_time(process) != key.creation_time:
            raise ProcessLookupError(key.pid)  # the pid belongs to someone else by now
        size = 512
        while size <= 32768:
            buffer = ctypes.create_unicode_buffer(size)
            length = wintypes.DWORD(size)
            if _k32.QueryFullProcessImageNameW(process, 0, buffer, ctypes.byref(length)):
                info = os.stat(buffer.value)
                return buffer.value, (info.st_dev, info.st_ino)
            code = ctypes.get_last_error()
            if code != ERROR_INSUFFICIENT_BUFFER:
                raise ctypes.WinError(code)
            size *= 2
        raise OSError("image path limit")
    finally:
        _k32.CloseHandle(process)
