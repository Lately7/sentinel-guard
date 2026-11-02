"""Low-privilege scan worker processes (A2; R13 §2, R13b P5).

Untrusted file formats (ZIP, PE, YARA-X) are parsed in a child process that
runs with a restricted copy of the caller's own token (all privileges but
SeChangeNotify removed, Administrators disabled), at **low integrity**, inside
a Job Object (memory cap, one process, killed when the job handle closes).
It inherits only its two pipe handles and gets a minimal environment.

A restricted copy of the caller's primary token needs no extra privilege for
CreateProcessAsUserW (R13b P5), so this runs and is tested unelevated; as the
LocalSystem service it does the same from the service token.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from typing import Sequence

if os.name == "nt":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)

    TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_ASSIGN_PRIMARY, TOKEN_ADJUST_DEFAULT = 0x8, 0x2, 0x1, 0x80
    DISABLE_MAX_PRIVILEGE = 0x1
    TokenIntegrityLevel = 25
    SE_GROUP_INTEGRITY = 0x20
    CREATE_SUSPENDED = 0x4
    CREATE_NO_WINDOW = 0x08000000
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


class WorkerError(OSError):
    pass


def _fail(what: str) -> WorkerError:
    code = ctypes.get_last_error()
    return WorkerError(code, f"{what} failed (Windows error {code})")


def _restricted_low_token() -> int:
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
            if not _adv.CreateRestrictedToken(own, DISABLE_MAX_PRIVILEGE, 1, ctypes.byref(disable),
                                              0, None, 0, None, ctypes.byref(restricted)):
                raise _fail("CreateRestrictedToken")
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
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    entries = [f"SystemRoot={sysroot}", f"PATH={sysroot}\\System32"]
    block = "\0".join(entries) + "\0\0"
    return ctypes.create_unicode_buffer(block, len(block))


class Worker:
    """A running restricted worker; `stdin`/`stdout` are binary pipe files."""

    def __init__(self, process: int, thread: int, job: int, pid: int, stdin, stdout) -> None:
        self._process, self._thread, self._job = process, thread, job
        self.pid, self.stdin, self.stdout = pid, stdin, stdout

    def wait(self, timeout: float) -> int | None:
        if _k32.WaitForSingleObject(self._process, int(timeout * 1000)) != WAIT_OBJECT_0:
            return None
        code = wintypes.DWORD()
        _k32.GetExitCodeProcess(self._process, ctypes.byref(code))
        return code.value

    def kill(self) -> None:
        """Closing the job kills the worker (KILL_ON_JOB_CLOSE)."""
        for f in (self.stdin, self.stdout):
            try:
                f.close()
            except OSError:
                pass
        for h in (self._job, self._thread):
            if h:
                _k32.CloseHandle(h)
        self._job = self._thread = 0
        self.wait(5)
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
           python: str | None = None, cwd: str | None = None) -> Worker:
    """Start `python -I -B <args...>` as a restricted, low-integrity, jobbed worker."""
    if os.name != "nt":
        raise WorkerError(0, "restricted workers need Windows")
    import msvcrt
    import subprocess

    exe = python or interpreter()
    cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline([exe, "-I", "-B", *args]))
    child_in_r, child_in_w = _pipe()
    child_out_r, child_out_w = _pipe()
    # Our ends must not be inherited by the child.
    _k32.SetHandleInformation(child_in_w, HANDLE_FLAG_INHERIT, 0)
    _k32.SetHandleInformation(child_out_r, HANDLE_FLAG_INHERIT, 0)
    token = job = 0
    attrs = None
    try:
        token = _restricted_low_token()
        job = _job(memory_limit)
        size = ctypes.c_size_t()
        _k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        attrs = ctypes.create_string_buffer(size.value)
        if not _k32.InitializeProcThreadAttributeList(attrs, 1, 0, ctypes.byref(size)):
            raise _fail("InitializeProcThreadAttributeList")
        # Only these two handles are inherited, whatever else is inheritable
        # in this process (the service may hold many).
        handles = (wintypes.HANDLE * 2)(child_in_r, child_out_w)
        if not _k32.UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles,
                                              ctypes.sizeof(handles), None, None):
            raise _fail("UpdateProcThreadAttribute")
        si = STARTUPINFOEXW()
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        si.StartupInfo.hStdInput = child_in_r
        si.StartupInfo.hStdOutput = child_out_w
        si.StartupInfo.hStdError = child_out_w
        si.lpAttributeList = ctypes.cast(attrs, ctypes.c_void_p)
        pi = PROCESS_INFORMATION()
        env = _environment()
        flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT
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
        child_in_w = child_out_r = 0
        worker = Worker(pi.hProcess, pi.hThread, job, pi.dwProcessId, stdin, stdout)
        job = 0
        return worker
    finally:
        if attrs is not None:
            _k32.DeleteProcThreadAttributeList(attrs)
        for h in (token, job, child_in_r, child_out_w, child_in_w, child_out_r):
            if h:
                _k32.CloseHandle(h)
