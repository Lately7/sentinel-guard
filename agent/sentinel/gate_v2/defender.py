"""Conservative, generation-bound Microsoft Defender path adapter."""

from __future__ import annotations

import glob
import hashlib
import ctypes
import os
import queue
import re
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from ctypes import wintypes

from . import identity
from .policy import classify_defender_name
from .contract import (CONTRACT_VERSION, ByteRange, CancellationToken, Category,
                       Coverage, EngineResult, Evidence, FileIdentity, ScanError,
                       ScanRequest, StageStatus, Strength, VerdictCode)

_NAME = re.compile(r"^[ \t]*Threat[ \t]*:[ \t]*([^\r\n]+)[ \t]*$", re.I | re.M)
_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/!+ -]{0,127}\Z")
MAX_OUTPUT = 64 * 1024
ACTIVE_TTL_NS = 600_000_000_000
SCAN_CAP_NS = 90_000_000_000
Runner = Callable[[list[str], int, CancellationToken], tuple[int, str]]
Applicability = Callable[[int | None], tuple[str | None, str]]
_DEFENDER_SLOT = threading.BoundedSemaphore(1)


class _JobBasic(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]


class _JobCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in ("r", "w", "o", "rb", "wb", "ob")]


class _JobLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _JobBasic), ("IoInfo", _JobCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


class _ThreadEntry(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD), ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD)]


if os.name == "nt":
    _KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
    _KERNEL.CreateJobObjectW.restype = wintypes.HANDLE
    _KERNEL.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _KERNEL.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _KERNEL.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _KERNEL.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _KERNEL.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)]
    _KERNEL.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)]
    _KERNEL.OpenThread.restype = wintypes.HANDLE
    _KERNEL.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _KERNEL.ResumeThread.argtypes = [wintypes.HANDLE]
    _KERNEL.ResumeThread.restype = wintypes.DWORD


class _Cancelled(Exception):
    pass


def _applicability(deadline_ns: int | None = None) -> tuple[str | None, str]:
    if os.name != "nt":
        return None, "unknown"
    roots = [os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                          "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe")]
    def version(path: str) -> tuple[int, ...]:
        return tuple(int(part) for part in re.findall(r"\d+", os.path.basename(os.path.dirname(path))))
    candidates = sorted(glob.glob(roots[0]), key=version, reverse=True)
    candidates.append(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                                   "Windows Defender", "MpCmdRun.exe"))
    exe = next((path for path in candidates if os.path.isfile(path)), None)
    if exe is None:
        return None, "unknown"
    script = ("(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
              "| Where-Object displayName -eq 'Windows Defender').productState")
    try:
        timeout = (20.0 if deadline_ns is None else
                   min(20.0, max(0.0, (deadline_ns - time.monotonic_ns()) / 1e9)))
        if timeout <= 0:
            return exe, "unknown"
        powershell = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        completed = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                                   capture_output=True, text=True, timeout=timeout, shell=False,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        state = int((completed.stdout or "").strip().splitlines()[0])
        return exe, "active" if completed.returncode == 0 and state & 0x1000 else "passive" if completed.returncode == 0 else "unknown"
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        return exe, "unknown"


def _run(argv: list[str], deadline_ns: int, cancel: CancellationToken) -> tuple[int, str]:
    """Run inside a kill-on-close Job Object; close it on every exit path."""
    if os.name != "nt":
        raise OSError("Defender is Windows-only")
    kernel = _KERNEL
    KILL_ON_CLOSE = 0x2000

    def resume(pid: int) -> None:
        snapshot = kernel.CreateToolhelp32Snapshot(0x4, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot")
        try:
            entry = _ThreadEntry()
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
        limits = _JobLimits()
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
                # MpCmdRun includes paths in the console code page; only ASCII threat names are parsed.
                # Real Defender output could not be checked on this machine because Defender is passive.
                return process.returncode, output.decode("latin-1")
            output.extend(block)
            if len(output) > MAX_OUTPUT:
                return 1, "\0"  # typed parse error, no raw output
    finally:
        stop_read.set()
        kernel.CloseHandle(job)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if process is not None and process.stdout is not None:
            process.stdout.close()


@dataclass
class DefenderAdapter:
    applicability: Applicability = _applicability
    runner: Runner = _run
    clock: Callable[[], int] = time.monotonic_ns

    engine_id = "defender"
    reopens_path = True

    def __post_init__(self) -> None:
        self._ready_at = -ACTIVE_TTL_NS
        self._ready: tuple[str | None, str] = (None, "unknown")
        self._ready_lock = threading.Lock()

    def readiness(self) -> str:
        exe, state = self._applicable()
        return "READY" if state == "active" and exe else "NOT_INSTALLED" if not exe else "PASSIVE" if state == "passive" else "APPLICABILITY_UNKNOWN"

    def _applicable(self, deadline_ns: int | None = None,
                    cancel: CancellationToken | None = None) -> tuple[str | None, str]:
        while not self._ready_lock.acquire(timeout=0.05):
            if (cancel is not None and cancel.cancelled()) or (deadline_ns is not None and self.clock() >= deadline_ns):
                return None, "unknown"
        try:
            now = self.clock()
            ttl = 30_000_000_000 if self._ready[1] == "unknown" else ACTIVE_TTL_NS
            if now - self._ready_at >= ttl:
                finished = threading.Event()
                observed: list[tuple[str | None, str]] = [(None, "unknown")]
                def probe() -> None:
                    try:
                        observed[0] = self.applicability(deadline_ns)
                    except Exception:
                        pass
                    finally:
                        finished.set()
                threading.Thread(target=probe, daemon=True).start()
                while not finished.wait(0.05):
                    if (cancel is not None and cancel.cancelled()) or (deadline_ns is not None and self.clock() >= deadline_ns):
                        return None, "unknown"
                self._ready = observed[0]
                self._ready_at = self.clock()
            return self._ready
        finally:
            self._ready_lock.release()

    def scan(self, request: ScanRequest, measured: FileIdentity,
             cancel: CancellationToken) -> EngineResult:
        start = self.clock()
        status = StageStatus.UNAVAILABLE
        code = "NOT_INSTALLED"
        evidence: tuple[Evidence, ...] = ()
        coverage = Coverage(measured.size, (), "none", 0, 0, 0, 0, (), (), (), "unknown")
        exe, state = self._applicable(request.deadline_monotonic_ns, cancel)
        if cancel.cancelled():
            status, code = StageStatus.CANCELLED, "CANCELLED"
        elif self.clock() >= request.deadline_monotonic_ns:
            status, code = StageStatus.TIMEOUT, "DEADLINE"
        elif exe and state == "unknown":
            code = "APPLICABILITY_UNKNOWN"
        elif exe and state == "passive":
            code = "PASSIVE"
        elif exe and state == "active":
            if request.path is None:
                code = "PATH_REQUIRED"
            elif cancel.cancelled():
                status, code = StageStatus.CANCELLED, "CANCELLED"
            else:
                deadline = min(request.deadline_monotonic_ns, start + SCAN_CAP_NS)
                if self.clock() >= deadline:
                    status, code = StageStatus.TIMEOUT, "DEADLINE"
                else:
                    argv = [exe, "-Scan", "-ScanType", "3", "-File", measured.canonical_path or request.path,
                            "-DisableRemediation"]
                    acquired = False
                    try:
                        while not acquired and not cancel.cancelled() and self.clock() < deadline:
                            acquired = _DEFENDER_SLOT.acquire(timeout=min(0.1, max(0, (deadline - self.clock()) / 1e9)))
                        if cancel.cancelled():
                            raise _Cancelled()
                        if not acquired:
                            raise subprocess.TimeoutExpired(argv, 0)
                        returncode, output = self.runner(argv, deadline, cancel)
                        if (not isinstance(output, str) or len(output) > MAX_OUTPUT or
                              "\ufffd" in output or any(ord(char) < 32 and char not in "\r\n\t"
                                                           for char in output)):
                            status, code = StageStatus.ERROR, "OUTPUT_INVALID"
                        elif returncode == 2:
                            names = list(dict.fromkeys(name.strip() for name in _NAME.findall(output)
                                                      if _SAFE.fullmatch(name.strip())))
                            if names:
                                limited = len(names) > 16
                                evidence = tuple(Evidence("defender." + hashlib.sha256(name.encode()).hexdigest()[:24],
                                                      self.engine_id, name, name, *classify_defender_name(name),
                                                      "outer", None, (ByteRange(0, measured.size),),
                                                      "microsoft-defender", None, None, True,
                                                      "NAMED_THREAT", name == "EICAR_Test_File" or name.endswith("/EICAR_Test_File"))
                                                 for name in names[:16])
                                status, code = StageStatus.COMPLETED, "READY"
                                if limited:
                                    coverage = Coverage(measured.size, (), "none", 0, 0, 0, 0, (), (), ("THREAT_NAME_LIMIT",), "unknown")
                            else:
                                status, code = StageStatus.ERROR, "THREAT_NAME_MISSING_OR_INVALID"
                        elif self.clock() >= deadline:
                            status, code = StageStatus.TIMEOUT, "DEADLINE"
                        elif returncode == 0:
                            status, code = StageStatus.COMPLETED, "READY"
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
                    finally:
                        if acquired:
                            _DEFENDER_SLOT.release()
                    if status is StageStatus.COMPLETED:
                        # This extra negative check also protects callers using the adapter
                        # directly. The orchestrator performs full before/after revalidation.
                        checked = identity.revalidate(request.path, measured, rehash=False, cancel=cancel)
                        if not checked.ok:
                            status, code = StageStatus.CHANGED, checked.code
                        else:
                            limited = bool(coverage.limits_hit)
                            coverage = Coverage(measured.size,
                                                 (ByteRange(0, measured.size),) if measured.size else (),
                                                 "fixed_partial" if limited else "full", 0, 0, 0, 0,
                                                 (), (), ("THREAT_NAME_LIMIT",) if limited else (), "declared")
        verdict = (VerdictCode.MALICIOUS if status is StageStatus.COMPLETED and any(item.strength is Strength.CONCLUSIVE for item in evidence) else
                   VerdictCode.SUSPICIOUS if status is StageStatus.COMPLETED and evidence else VerdictCode.CLEAN
                   if status is StageStatus.COMPLETED else VerdictCode.UNKNOWN)
        error = (None if status is StageStatus.COMPLETED else
                 ScanError(code, "defender", code, status in (StageStatus.TIMEOUT,
                                                                StageStatus.ERROR, StageStatus.CHANGED)))
        return EngineResult(CONTRACT_VERSION, self.engine_id, request.file_id, measured,
                            status, verdict, coverage, evidence, None, None, None, code,
                            start, max(0, (self.clock() - start) // 1_000_000), error)
