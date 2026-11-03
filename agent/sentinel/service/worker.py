"""Low-privilege scan worker processes (A2; R13 §2, R13b P5).

Untrusted file formats (ZIP, PE, YARA-X) are parsed in a child process that
runs with a restricted copy of the caller's own token (all privileges but
SeChangeNotify removed, Administrators disabled), at **low integrity**, inside
a Job Object (memory cap, one process, killed when the job handle closes).
It inherits only its three pipe handles and gets a minimal environment.

A restricted copy of the caller's primary token needs no extra privilege for
CreateProcessAsUserW (R13b P5), so this runs and is tested unelevated. As the
LocalSystem service it does the same from the service token, with restricting
SIDs and a private desktop: that worker holds no user's identity, so the Users
and Everyone entries on the runtime are all it can use, and it needs a desktop
it can open before user32 lets it live (measured, REVIEWS.md fifth round).
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
from ctypes import wintypes
from typing import BinaryIO, Sequence

# What the restricted pass of the access check may use. Python has to load system
# DLLs and reach the object namespace, which these three can. None of them is on the
# state tree or a user's profile, and low integrity stops every write.
RESTRICTING_SIDS = ("S-1-5-32-545", "S-1-1-0", "S-1-5-12")
WORKER_STATION = "SentinelGuardWorker"
LOCAL_SYSTEM = "S-1-5-18"
ERROR_ACCESS_DENIED = 5
_desktop: str | None = None
_desktop_handles: tuple[int, int] = (0, 0)  # kept open: the objects live as long as a handle does
_desktop_lock = threading.Lock()

if os.name == "nt":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _u32 = ctypes.WinDLL("user32", use_last_error=True)

    TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_ASSIGN_PRIMARY, TOKEN_ADJUST_DEFAULT = 0x8, 0x2, 0x1, 0x80
    DISABLE_MAX_PRIVILEGE = 0x1
    TokenIntegrityLevel = 25
    SE_GROUP_INTEGRITY = 0x20
    CREATE_SUSPENDED = 0x4
    # Not CREATE_NO_WINDOW: its hidden console needs a conhost this token cannot attach to.
    DETACHED_PROCESS = 0x8
    CREATE_UNICODE_ENVIRONMENT = 0x400
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000
    STARTF_USESTDHANDLES = 0x100
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
    HANDLE_FLAG_INHERIT = 0x1
    JobObjectExtendedLimitInformation = 9
    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x8
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x400
    WAIT_OBJECT_0, WAIT_TIMEOUT = 0, 0x102
    GENERIC_ALL = 0x10000000
    UOI_NAME = 2

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

    class STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rb", "wb", "ob")]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION), ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CreatePipe.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
                                ctypes.c_void_p, wintypes.DWORD]
    _k32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    _k32.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                       ctypes.POINTER(ctypes.c_size_t)]
    _k32.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
                                               ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
    _k32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _k32.ResumeThread.argtypes = [wintypes.HANDLE]
    _k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _k32.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    _k32.GetWindowsDirectoryW.restype = wintypes.UINT
    _adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _adv.CreateRestrictedToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                           ctypes.POINTER(wintypes.HANDLE)]
    _adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    _adv.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _adv.CreateProcessAsUserW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
                                          ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p,
                                          wintypes.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(PROCESS_INFORMATION)]
    _k32.LocalFree.argtypes = [ctypes.c_void_p]
    _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    _u32.CreateWindowStationW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    _u32.CreateWindowStationW.restype = wintypes.HANDLE
    _u32.CreateDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD,
                                    wintypes.DWORD, ctypes.c_void_p]
    _u32.CreateDesktopW.restype = wintypes.HANDLE
    _u32.GetProcessWindowStation.restype = wintypes.HANDLE
    _u32.SetProcessWindowStation.argtypes = [wintypes.HANDLE]
    _u32.GetUserObjectInformationW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.c_void_p]


class WorkerError(OSError):
    pass


def _fail(what: str) -> WorkerError:
    code = ctypes.get_last_error()
    return WorkerError(code, f"{what} failed (Windows error {code})")


def _restricted_low_token(service_sid: str | None = None) -> int:
    """Restricted, low-integrity primary token derived from our own."""
    own = wintypes.HANDLE()
    access = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT
    if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), access, ctypes.byref(own)):
        raise _fail("OpenProcessToken")
    try:
        admins = ctypes.c_void_p()
        if not _adv.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(admins)):
            raise _fail("ConvertStringSidToSid")
        try:
            # Administrators becomes deny-only, so an elevated parent (the
            # service) still yields a worker without admin access.
            disable = SID_AND_ATTRIBUTES(admins, 0)
            restricted = wintypes.HANDLE()
            sids: list[ctypes.c_void_p] = []
            try:
                for name in (*RESTRICTING_SIDS, service_sid) if service_sid else ():
                    sid = ctypes.c_void_p()
                    if not _adv.ConvertStringSidToSidW(name, ctypes.byref(sid)):
                        raise _fail("ConvertStringSidToSid(restricting)")
                    sids.append(sid)
                entries = (SID_AND_ATTRIBUTES * len(sids))(*(SID_AND_ATTRIBUTES(sid, 0) for sid in sids))
                if not _adv.CreateRestrictedToken(own, DISABLE_MAX_PRIVILEGE, 1, ctypes.byref(disable),
                                                  0, None, len(sids), ctypes.byref(entries) if sids else None,
                                                  ctypes.byref(restricted)):
                    raise _fail("CreateRestrictedToken")
            finally:
                for sid in sids:
                    _k32.LocalFree(sid)
        finally:
            _k32.LocalFree(admins)
    finally:
        _k32.CloseHandle(own)
    low = ctypes.c_void_p()
    if not _adv.ConvertStringSidToSidW("S-1-16-4096", ctypes.byref(low)):
        _k32.CloseHandle(restricted)
        raise _fail("ConvertStringSidToSid")
    try:
        label = SID_AND_ATTRIBUTES(low, SE_GROUP_INTEGRITY)
        if not _adv.SetTokenInformation(restricted, TokenIntegrityLevel, ctypes.byref(label),
                                        ctypes.sizeof(label) + 64):
            _k32.CloseHandle(restricted)
            raise _fail("SetTokenInformation(integrity)")
    finally:
        _k32.LocalFree(low)
    return restricted.value


def _private_desktop() -> str:
    """station\\desktop that a restricted, low-integrity worker can open.

    ctypes brings in user32, which ends a process that cannot open its desktop
    (measured: both the RESTRICTED entry and the low label are needed). Session 0's
    station is shared with other services, so the service makes its own. Its handles
    stay open for the life of the process, or the objects would go with them.
    """
    global _desktop, _desktop_handles
    with _desktop_lock:
        if _desktop is not None:
            return _desktop
        from .winpipe import current_process_caller

        owner = current_process_caller().sid
        sddl = f"D:(A;;GA;;;SY)(A;;GA;;;{owner})(A;;GA;;;RC)S:(ML;;NW;;;LW)"
        sd = ctypes.c_void_p()
        if not _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
            raise _fail("ConvertStringSecurityDescriptorToSecurityDescriptor")
        try:
            attrs = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
            # By name: unnamed, SYSTEM gets Service-0x0-3e7$, the station every LocalSystem
            # service shares, and this descriptor is ignored. Below SYSTEM a name is refused
            # (measured: error 5), while unnamed there does make a new station.
            station = _u32.CreateWindowStationW(WORKER_STATION, 0, GENERIC_ALL, ctypes.byref(attrs))
            if not station and ctypes.get_last_error() == ERROR_ACCESS_DENIED and owner != LOCAL_SYSTEM:
                station = _u32.CreateWindowStationW(None, 0, GENERIC_ALL, ctypes.byref(attrs))
            if not station:
                raise _fail("CreateWindowStation")
            previous = _u32.GetProcessWindowStation()
            # CreateDesktop has no station argument: it uses this process's current one.
            if not _u32.SetProcessWindowStation(station):
                raise _fail("SetProcessWindowStation")
            try:
                desktop = _u32.CreateDesktopW("Worker", None, None, 0, GENERIC_ALL, ctypes.byref(attrs))
                if not desktop:
                    raise _fail("CreateDesktop")
            finally:
                _u32.SetProcessWindowStation(previous)
            name = ctypes.create_unicode_buffer(256)
            if not _u32.GetUserObjectInformationW(station, UOI_NAME, name, ctypes.sizeof(name), None):
                raise _fail("GetUserObjectInformation")
        finally:
            _k32.LocalFree(sd)
        _desktop_handles = (station, desktop)
        _desktop = f"{name.value}\\Worker"
        return _desktop


def _job(memory_limit: int) -> int:
    job = _k32.CreateJobObjectW(None, None)
    if not job:
        raise _fail("CreateJobObject")
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                                             | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                                             | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
    # One process: a parser bug cannot spawn helpers.
    info.BasicLimitInformation.ActiveProcessLimit = 1
    info.ProcessMemoryLimit = memory_limit
    if not _k32.SetInformationJobObject(job, JobObjectExtendedLimitInformation, ctypes.byref(info),
                                        ctypes.sizeof(info)):
        _k32.CloseHandle(job)
        raise _fail("SetInformationJobObject")
    return job


def _environment() -> ctypes.Array[ctypes.c_wchar]:
    # Nothing from the parent's environment beyond what Windows itself needs:
    # no PYTHON*, no PATH entries a user could plant DLLs in.
    buf = ctypes.create_unicode_buffer(32768)
    length = _k32.GetWindowsDirectoryW(buf, len(buf))
    if not length or length >= len(buf):
        raise _fail("GetWindowsDirectoryW")
    sysroot = buf.value
    entries = [f"SystemRoot={sysroot}", f"PATH={sysroot}\\System32"]
    block = "\0".join(entries) + "\0\0"
    return ctypes.create_unicode_buffer(block, len(block))


class Worker:
    """A running restricted worker; `stdin`/`stdout` are binary pipe files."""

    def __init__(self, process: int, thread: int, job: int, pid: int,
                 stdin: BinaryIO, stdout: BinaryIO, stderr: BinaryIO) -> None:
        self._process, self._thread, self._job = process, thread, job
        self.pid, self.stdin, self.stdout, self.stderr = pid, stdin, stdout, stderr
        self._stderr_lock = threading.Lock()
        self._stderr_tail = b""
        self._stderr_reader = threading.Thread(target=self._drain_stderr, daemon=True, name="worker-stderr")
        self._stderr_reader.start()

    def _drain_stderr(self) -> None:
        try:
            while chunk := self.stderr.read(4096):
                with self._stderr_lock:
                    self._stderr_tail = (self._stderr_tail + chunk)[-2048:]
        except (OSError, ValueError):
            pass

    def stderr_tail(self) -> str:
        with self._stderr_lock:
            return self._stderr_tail.decode("utf-8", "replace")

    def wait(self, timeout: float) -> int | None:
        if _k32.WaitForSingleObject(self._process, int(timeout * 1000)) != WAIT_OBJECT_0:
            return None
        code = wintypes.DWORD()
        _k32.GetExitCodeProcess(self._process, ctypes.byref(code))
        return code.value

    def kill(self) -> None:
        """Closing the job kills the worker (KILL_ON_JOB_CLOSE)."""
        for h in (self._job, self._thread):
            if h:
                _k32.CloseHandle(h)
        self._job = self._thread = 0
        if self._process:
            self.wait(5)
        self._stderr_reader.join(timeout=1)
        for f in (self.stdin, self.stdout, self.stderr):
            try:
                f.close()
            except OSError:
                pass
        if self._process:
            _k32.CloseHandle(self._process)
            self._process = 0

    close = kill


def _pipe() -> tuple[int, int]:
    sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
    r, w = wintypes.HANDLE(), wintypes.HANDLE()
    if not _k32.CreatePipe(ctypes.byref(r), ctypes.byref(w), ctypes.byref(sa), 0):
        raise _fail("CreatePipe")
    return r.value, w.value


def interpreter() -> str:
    # A venv's python.exe is a launcher that starts the base interpreter as a
    # second process, which the job's one-process limit forbids; run the base
    # interpreter and hand it the venv's site-packages through bootstrap().
    return getattr(sys, "_base_executable", None) or sys.executable


def bootstrap(module: str) -> list[str]:
    """`-c` arguments that put this package and its dependencies on sys.path
    (isolated mode ignores PYTHONPATH and the venv) and run `module`."""
    paths = [os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))]
    paths += [p for p in sys.path if p.endswith("site-packages")]
    code = f"import sys, runpy; sys.path[:0] = {paths!r}; runpy.run_module({module!r}, run_name='__main__')"
    return ["-c", code]


def launch(args: Sequence[str], *, memory_limit: int = 512 * 1024 * 1024,
           python: str | None = None, cwd: str | None = None,
           service_sid: str | None = None) -> Worker:
    """Start `python -I -B <args...>` as a restricted, low-integrity, jobbed worker."""
    if os.name != "nt":
        raise WorkerError(0, "restricted workers need Windows")
    import msvcrt
    import subprocess

    exe = python or interpreter()
    cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline([exe, "-I", "-B", *args]))
    child_in_r = child_in_w = child_out_r = child_out_w = child_err_r = child_err_w = 0
    token = job = 0
    attrs = None
    try:
        child_in_r, child_in_w = _pipe()
        child_out_r, child_out_w = _pipe()
        child_err_r, child_err_w = _pipe()
        # Our ends must not be inherited by the child.
        _k32.SetHandleInformation(child_in_w, HANDLE_FLAG_INHERIT, 0)
        _k32.SetHandleInformation(child_out_r, HANDLE_FLAG_INHERIT, 0)
        _k32.SetHandleInformation(child_err_r, HANDLE_FLAG_INHERIT, 0)
        token = _restricted_low_token(service_sid)
        job = _job(memory_limit)
        size = ctypes.c_size_t()
        _k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        attrs = ctypes.create_string_buffer(size.value)
        if not _k32.InitializeProcThreadAttributeList(attrs, 1, 0, ctypes.byref(size)):
            raise _fail("InitializeProcThreadAttributeList")
        # Only these three handles are inherited, whatever else is inheritable
        # in this process (the service may hold many).
        handles = (wintypes.HANDLE * 3)(child_in_r, child_out_w, child_err_w)
        if not _k32.UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles,
                                              ctypes.sizeof(handles), None, None):
            raise _fail("UpdateProcThreadAttribute")
        si = STARTUPINFOEXW()
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        if service_sid:
            si.StartupInfo.lpDesktop = _private_desktop()
        si.StartupInfo.hStdInput = child_in_r
        si.StartupInfo.hStdOutput = child_out_w
        si.StartupInfo.hStdError = child_err_w
        si.lpAttributeList = ctypes.cast(attrs, ctypes.c_void_p)
        pi = PROCESS_INFORMATION()
        env = _environment()
        flags = CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT
        if not _adv.CreateProcessAsUserW(token, exe, cmdline, None, None, True, flags, env,
                                         cwd or os.path.dirname(exe), ctypes.byref(si), ctypes.byref(pi)):
            raise _fail("CreateProcessAsUser")
        # Into the job before it runs a single instruction.
        if not _k32.AssignProcessToJobObject(job, pi.hProcess):
            err = _fail("AssignProcessToJobObject")
            _k32.TerminateProcess(pi.hProcess, 1)
            _k32.CloseHandle(pi.hThread)
            _k32.CloseHandle(pi.hProcess)
            raise err
        _k32.ResumeThread(pi.hThread)
        stdin = os.fdopen(msvcrt.open_osfhandle(child_in_w, 0), "wb", buffering=0)
        stdout = os.fdopen(msvcrt.open_osfhandle(child_out_r, os.O_RDONLY), "rb", buffering=0)
        stderr = os.fdopen(msvcrt.open_osfhandle(child_err_r, os.O_RDONLY), "rb", buffering=0)
        child_in_w = child_out_r = child_err_r = 0
        worker = Worker(pi.hProcess, pi.hThread, job, pi.dwProcessId, stdin, stdout, stderr)
        job = 0
        return worker
    finally:
        if attrs is not None:
            _k32.DeleteProcThreadAttributeList(attrs)
        for h in (token, job, child_in_r, child_out_w, child_err_w, child_in_w, child_out_r, child_err_r):
            if h:
                _k32.CloseHandle(h)
