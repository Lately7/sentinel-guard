"""Conservative, generation-bound Microsoft Defender path adapter."""

from __future__ import annotations

import glob
import os
import queue
import re
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from . import identity
from .contract import (CONTRACT_VERSION, ByteRange, CancellationToken, Category,
                       Coverage, EngineResult, Evidence, FileIdentity, ScanError,
                       ScanRequest, StageStatus, Strength, VerdictCode)

_NAME = re.compile(r"^[ \t]*Threat[ \t]*:[ \t]*([^\r\n]+)[ \t]*$", re.I | re.M)
_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/!+ -]{0,127}\Z")
MAX_OUTPUT = 64 * 1024
ACTIVE_TTL_NS = 600_000_000_000
SCAN_CAP_NS = 90_000_000_000
Runner = Callable[[list[str], int, CancellationToken], tuple[int, str]]
Applicability = Callable[[], tuple[str | None, bool]]


class _Cancelled(Exception):
    pass


def _applicability(deadline_ns: int | None = None) -> tuple[str | None, bool]:
    if os.name != "nt":
        return None, False
    roots = [os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                          "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe")]
    candidates = sorted(glob.glob(roots[0]), reverse=True)
    candidates.append(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                                   "Windows Defender", "MpCmdRun.exe"))
    exe = next((path for path in candidates if os.path.isfile(path)), None)
    if exe is None:
        return None, False
    script = ("(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
              "| Where-Object displayName -eq 'Windows Defender').productState")
    try:
        timeout = (20.0 if deadline_ns is None else
                   min(20.0, max(0.0, (deadline_ns - time.monotonic_ns()) / 1e9)))
        if timeout <= 0:
            return exe, False
        completed = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                                   capture_output=True, text=True, timeout=timeout, shell=False,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        state = int((completed.stdout or "").strip().splitlines()[0])
        return exe, completed.returncode == 0 and bool(state & 0x1000)
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        return exe, False


def _run(argv: list[str], deadline_ns: int, cancel: CancellationToken) -> tuple[int, str]:
    """Run inside a kill-on-close Job Object; close it on every exit path."""
    if os.name != "nt":
        raise OSError("Defender is Windows-only")
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    KILL_ON_CLOSE = 0x2000
    class Basic(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]
    class Counters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in ("r", "w", "o", "rb", "wb", "ob")]
    class Limits(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", Counters),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
    class ThreadEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ThreadID", wintypes.DWORD), ("th32OwnerProcessID", wintypes.DWORD),
                    ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD)]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
    kernel.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
    kernel.OpenThread.restype = wintypes.HANDLE
    kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel.ResumeThread.restype = wintypes.DWORD

    def resume(pid: int) -> None:
        snapshot = kernel.CreateToolhelp32Snapshot(0x4, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot")
        try:
            entry = ThreadEntry()
            entry.dwSize = ctypes.sizeof(entry)
            found = kernel.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.th32OwnerProcessID == pid:
                    thread = kernel.OpenThread(0x0002, False, entry.th32ThreadID)
                    if not thread:
                        raise OSError(ctypes.get_last_error(), "OpenThread")
                    try:
                        if kernel.ResumeThread(thread) == 0xffffffff:
                            raise OSError(ctypes.get_last_error(), "ResumeThread")
                        return
                    finally:
                        kernel.CloseHandle(thread)
                found = kernel.Thread32Next(snapshot, ctypes.byref(entry))
            raise OSError("suspended Defender thread not found")
        finally:
            kernel.CloseHandle(snapshot)
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW")
    process: subprocess.Popen[bytes] | None = None
    stop_read = threading.Event()
    try:
        limits = Limits()
        limits.BasicLimitInformation.LimitFlags = KILL_ON_CLOSE
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject")
        # A suspended child cannot scan before it is assigned to the job.
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, shell=False,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) | 0x4)
        if not kernel.AssignProcessToJobObject(job, int(process._handle)):
            process.kill()
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject")
        resume(process.pid)
        chunks: queue.Queue[bytes] = queue.Queue(maxsize=32)
        def drain() -> None:
            assert process is not None and process.stdout is not None
            try:
                while block := process.stdout.read(4096):
                    while not stop_read.is_set():
                        try:
                            chunks.put(block, timeout=0.1)
                            break
                        except queue.Full:
                            pass
                    if stop_read.is_set():
                        return
            finally:
                while not stop_read.is_set():
                    try:
                        chunks.put(b"", timeout=0.1)
                        break
                    except queue.Full:
                        pass
        threading.Thread(target=drain, daemon=True).start()
        output = bytearray()
        while True:
            if cancel.cancelled():
                raise _Cancelled()
            remaining = (deadline_ns - time.monotonic_ns()) / 1e9
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, 0)
            try:
                block = chunks.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            if not block:
                process.wait(timeout=max(0.001, (deadline_ns - time.monotonic_ns()) / 1e9))
                return process.returncode, output.decode("utf-8", errors="replace")
            output.extend(block)
            if len(output) > MAX_OUTPUT:
                return 1, "\0"  # typed parse error, no raw output
    finally:
        stop_read.set()
        kernel.CloseHandle(job)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()


@dataclass
class DefenderAdapter:
    applicability: Applicability = _applicability
    runner: Runner = _run
    clock: Callable[[], int] = time.monotonic_ns

    engine_id = "defender"
    reopens_path = True

    def __post_init__(self) -> None:
        self._ready_at = -ACTIVE_TTL_NS
        self._ready: tuple[str | None, bool] = (None, False)

    def readiness(self) -> str:
        exe, active = self._applicable()
        return "READY" if exe and active else "NOT_INSTALLED" if not exe else "PASSIVE"

    def _applicable(self, deadline_ns: int | None = None) -> tuple[str | None, bool]:
        now = self.clock()
        if now - self._ready_at >= ACTIVE_TTL_NS:
            try:
                self._ready = (_applicability(deadline_ns) if self.applicability is _applicability
                               else self.applicability())
            except Exception:
                self._ready = (None, False)
            self._ready_at = (-ACTIVE_TTL_NS if deadline_ns is not None and
                              self.clock() >= deadline_ns else now)
        return self._ready

    def scan(self, request: ScanRequest, measured: FileIdentity,
             cancel: CancellationToken) -> EngineResult:
        start = self.clock()
        status = StageStatus.UNAVAILABLE
        code = "NOT_INSTALLED"
        evidence: tuple[Evidence, ...] = ()
        coverage = Coverage(measured.size, (), "none", 0, 0, 0, 0, (), (), (), "unknown")
        exe, active = self._applicable(request.deadline_monotonic_ns)
        if self.clock() >= request.deadline_monotonic_ns:
            status, code = StageStatus.TIMEOUT, "DEADLINE"
        elif exe and not active:
            code = "PASSIVE"
        elif exe and active:
            if request.path is None:
                code = "PATH_REQUIRED"
            elif cancel.cancelled():
                status, code = StageStatus.CANCELLED, "CANCELLED"
            else:
                deadline = min(request.deadline_monotonic_ns, start + SCAN_CAP_NS)
                if self.clock() >= deadline:
                    status, code = StageStatus.TIMEOUT, "DEADLINE"
                else:
                    argv = [exe, "-Scan", "-ScanType", "3", "-File", request.path,
                            "-DisableRemediation"]
                    try:
                        returncode, output = self.runner(argv, deadline, cancel)
                        if self.clock() >= deadline:
                            status, code = StageStatus.TIMEOUT, "DEADLINE"
                        elif (not isinstance(output, str) or len(output) > MAX_OUTPUT or
                              "\ufffd" in output or any(ord(char) < 32 and char not in "\r\n\t"
                                                           for char in output)):
                            status, code = StageStatus.ERROR, "OUTPUT_INVALID"
                        elif returncode == 0:
                            status, code = StageStatus.COMPLETED, "READY"
                        elif returncode == 2:
                            names = [name.strip() for name in _NAME.findall(output)]
                            if len(names) == 1 and _SAFE.fullmatch(names[0]):
                                name = names[0]
                                evidence = (Evidence("defender.named_threat", self.engine_id, name,
                                                     name, Category.MALWARE, Strength.CONCLUSIVE,
                                                     "outer", None, (ByteRange(0, measured.size),),
                                                     "microsoft-defender", None, None, True,
                                                     "NAMED_THREAT"),)
                                status, code = StageStatus.COMPLETED, "READY"
                            else:
                                status, code = StageStatus.ERROR, "THREAT_NAME_MISSING_OR_INVALID"
                        else:
                            status, code = StageStatus.ERROR, "EXIT_NONZERO"
                    except subprocess.TimeoutExpired:
                        status, code = StageStatus.TIMEOUT, "DEADLINE"
                    except _Cancelled:
                        status, code = StageStatus.CANCELLED, "CANCELLED"
                    except OSError:
                        status, code = StageStatus.UNAVAILABLE, "RUNNER_UNAVAILABLE"
                    except Exception:
                        status, code = StageStatus.ERROR, "RUNNER_ERROR"
                    if status is StageStatus.COMPLETED:
                        # This extra negative check also protects callers using the adapter
                        # directly. The orchestrator performs full before/after revalidation.
                        checked = identity.revalidate(request.path, measured, rehash=True)
                        if not checked.ok:
                            status, code, evidence = StageStatus.CHANGED, checked.code, ()
                        else:
                            coverage = Coverage(measured.size,
                                                (ByteRange(0, measured.size),) if measured.size else (),
                                                "full", 0, 0, 0, 0, (), (), (), "declared")
        verdict = (VerdictCode.MALICIOUS if evidence else VerdictCode.CLEAN
                   if status is StageStatus.COMPLETED else VerdictCode.UNKNOWN)
        error = (None if status is StageStatus.COMPLETED else
                 ScanError(code, "defender", code, status in (StageStatus.TIMEOUT,
                                                                StageStatus.ERROR, StageStatus.CHANGED)))
        return EngineResult(CONTRACT_VERSION, self.engine_id, request.file_id, measured,
                            status, verdict, coverage, evidence, None, None, None, code,
                            start, max(0, (self.clock() - start) // 1_000_000), error)
