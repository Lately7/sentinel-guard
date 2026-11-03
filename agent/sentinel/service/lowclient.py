"""Run a single harmless approval probe with the interactive shell's token."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
from ctypes import wintypes
from pathlib import Path
from typing import Callable

from .client import ServiceClient, ServiceError, ServiceUnavailable

IMPOSSIBLE_PLAN_ID = "sentinel-verify-no-plan"
TOKEN_QUERY = 0x8
TOKEN_DUPLICATE = 0x2
TOKEN_ASSIGN_PRIMARY = 0x1
TOKEN_ADJUST_DEFAULT = 0x80
TOKEN_ADJUST_SESSIONID = 0x100
TOKEN_ELEVATION_TYPE = 18
TOKEN_SESSION_ID = 12
ELEVATION_TYPE_FULL = 2
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SECURITY_IMPERSONATION = 2
TOKEN_PRIMARY = 1
STARTF_USESTDHANDLES = 0x100
CREATE_NO_WINDOW = 0x08000000
HANDLE_FLAG_INHERIT = 1
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
MAX_OUTPUT = 4096


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


class WindowsProbe:
    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Windows token probe requires Windows")
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.k32.GetCurrentProcess.restype = wintypes.HANDLE
        self.k32.GetCurrentProcessId.restype = wintypes.DWORD
        self.k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.k32.OpenProcess.restype = wintypes.HANDLE
        self.k32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        self.user.GetShellWindow.restype = wintypes.HWND
        self.user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        self.user.GetWindowThreadProcessId.restype = wintypes.DWORD
        self.k32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.k32.CreatePipe.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
                                       ctypes.POINTER(SECURITY_ATTRIBUTES), wintypes.DWORD]
        self.k32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
        self.k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.k32.WaitForSingleObject.restype = wintypes.DWORD
        self.k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                      ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        self.adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                              ctypes.POINTER(wintypes.HANDLE)]
        self.adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        self.adv.DuplicateTokenEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                                              ctypes.c_int, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
        self.adv.CreateProcessWithTokenW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR,
                                                     wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p,
                                                     wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
                                                     ctypes.POINTER(PROCESS_INFORMATION)]

    @staticmethod
    def _error(name: str) -> OSError:
        code = ctypes.get_last_error()
        return OSError(code, f"{name} failed (Windows error {code})")

    def close(self, token: int) -> None:
        self.k32.CloseHandle(token)

    def has_split_token(self) -> bool:
        own = wintypes.HANDLE()
        if not self.adv.OpenProcessToken(self.k32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(own)):
            raise self._error("OpenProcessToken")
        try:
            kind, size = wintypes.DWORD(), wintypes.DWORD()
            if not self.adv.GetTokenInformation(own, TOKEN_ELEVATION_TYPE, ctypes.byref(kind),
                                                ctypes.sizeof(kind), ctypes.byref(size)):
                raise self._error("GetTokenInformation(TokenElevationType)")
            return kind.value == ELEVATION_TYPE_FULL
        finally:
            self.k32.CloseHandle(own)

    def shell_token(self) -> tuple[int | None, str]:
        shell = self.user.GetShellWindow()
        if not shell:
            return None, "không có shell tương tác trong phiên này"
        pid = wintypes.DWORD()
        if not self.user.GetWindowThreadProcessId(shell, ctypes.byref(pid)) or not pid.value:
            raise self._error("GetWindowThreadProcessId")
        process = self.k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
        if not process:
            raise self._error("OpenProcess")
        source = wintypes.HANDLE()
        primary = wintypes.HANDLE()
        try:
            session = wintypes.DWORD()
            if not self.k32.ProcessIdToSessionId(self.k32.GetCurrentProcessId(), ctypes.byref(session)):
                raise self._error("ProcessIdToSessionId")
            if not self.adv.OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, ctypes.byref(source)):
                raise self._error("OpenProcessToken")
            shell_session, size = wintypes.DWORD(), wintypes.DWORD()
            if not self.adv.GetTokenInformation(source, TOKEN_SESSION_ID, ctypes.byref(shell_session),
                                                ctypes.sizeof(shell_session), ctypes.byref(size)):
                raise self._error("GetTokenInformation(TokenSessionId)")
            if shell_session.value != session.value:
                return None, "shell thuộc phiên khác với tiến trình kiểm tra"
            access = (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                      TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID)
            if not self.adv.DuplicateTokenEx(source, access, None, SECURITY_IMPERSONATION,
                                             TOKEN_PRIMARY, ctypes.byref(primary)):
                raise self._error("DuplicateTokenEx")
            if not primary.value:
                raise OSError("DuplicateTokenEx returned no handle")
            result = int(primary.value)
            primary = wintypes.HANDLE()
            return result, ""
        finally:
            if primary.value:
                self.k32.CloseHandle(primary)
            if source.value:
                self.k32.CloseHandle(source)
            self.k32.CloseHandle(process)

    def _wait_client(self, process: int) -> None:
        waited = self.k32.WaitForSingleObject(process, 15_000)
        if waited == WAIT_TIMEOUT:
            if not self.k32.TerminateProcess(process, 1):
                raise self._error("TerminateProcess")
            if self.k32.WaitForSingleObject(process, 5_000) != WAIT_OBJECT_0:
                raise OSError("ordinary client did not exit after termination")
            raise TimeoutError("ordinary client exceeded 15 s")
        if waited != WAIT_OBJECT_0:
            raise self._error("WaitForSingleObject")

    def run(self, token: int, python: Path, cwd: Path) -> tuple[int, bytes]:
        read, write = wintypes.HANDLE(), wintypes.HANDLE()
        sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
        if not self.k32.CreatePipe(ctypes.byref(read), ctypes.byref(write), ctypes.byref(sa), 0):
            raise self._error("CreatePipe")
        pi = PROCESS_INFORMATION()
        try:
            if not self.k32.SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0):
                raise self._error("SetHandleInformation")
            si = STARTUPINFOW()
            si.cb = ctypes.sizeof(si)
            si.dwFlags = STARTF_USESTDHANDLES
            si.hStdOutput = write
            si.hStdError = write
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline(
                [str(python), "-I", "-B", "-m", "sentinel.service.lowclient"]))
            if not self.adv.CreateProcessWithTokenW(token, 0, str(python), command, CREATE_NO_WINDOW,
                                                    None, str(cwd), ctypes.byref(si), ctypes.byref(pi)):
                raise self._error("CreateProcessWithTokenW")
            self.k32.CloseHandle(write)
            write = wintypes.HANDLE()
            self._wait_client(pi.hProcess)
            code = wintypes.DWORD()
            if not self.k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code)):
                raise self._error("GetExitCodeProcess")
            data = ctypes.create_string_buffer(MAX_OUTPUT)
            count = wintypes.DWORD()
            if not self.k32.ReadFile(read, data, MAX_OUTPUT, ctypes.byref(count), None):
                raise self._error("ReadFile")
            return int(code.value), data.raw[:count.value]
        finally:
            if pi.hProcess and self.k32.WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT:
                self.k32.TerminateProcess(pi.hProcess, 1)
                self.k32.WaitForSingleObject(pi.hProcess, 5_000)
            if pi.hThread:
                self.k32.CloseHandle(pi.hThread)
            if pi.hProcess:
                self.k32.CloseHandle(pi.hProcess)
            if write.value:
                self.k32.CloseHandle(write)
            if read.value:
                self.k32.CloseHandle(read)


def ask(client: Callable[[], ServiceClient] = ServiceClient) -> dict[str, str]:
    try:
        with client() as service:
            service.request("approve_plan", plan_id=IMPOSSIBLE_PLAN_ID, version=1)
    except ServiceUnavailable as exc:
        return {"result": "unavailable", "code": exc.code}
    except ServiceError as exc:
        return {"result": "refused", "code": exc.code}
    return {"result": "approved"}


def main() -> int:
    from .winpipe import current_process_caller

    try:
        caller = current_process_caller()
        if caller.integrity != "medium" or caller.is_admin:
            result = {"result": "wrong_token"}
        else:
            result = ask()
        print(json.dumps({**result, "integrity": caller.integrity, "admin": caller.is_admin}))
    except (OSError, ServiceError) as exc:
        print(json.dumps({"result": "unavailable", "code": type(exc).__name__}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
