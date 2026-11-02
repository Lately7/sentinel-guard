"""Elevated, plan-bound native confirmation and the tray's runas launcher."""

from __future__ import annotations

import argparse
import ctypes
import os
import re
from ctypes import wintypes
from pathlib import Path

from .client import ServiceClient
from .installer import registered_version
from .paths import active_version, installed_paths

TITLE = "Sentinel Guard - Xác nhận hành động quản trị"
PLAN_ID = re.compile(r"[0-9a-f]{32}\Z")
ERROR_CANCELLED = 1223
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102


class ConsentError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def validate_plan_id(plan_id: str) -> str:
    if not isinstance(plan_id, str) or not PLAN_ID.fullmatch(plan_id):
        raise ConsentError("BAD_PLAN_ID")
    return plan_id


def confirm(plan_id: str, *, client: ServiceClient | None = None,
            message_box: object | None = None) -> bool:
    plan_id = validate_plan_id(plan_id)
    own = client is None
    service = client or ServiceClient()
    try:
        plan = service.request("get_plan", plan_id=plan_id)
        if plan.get("plan_id") != plan_id or not isinstance(plan.get("summary"), str) or not isinstance(plan.get("version"), int):
            raise ConsentError("BAD_PLAN")
        show = message_box
        if show is None:
            if os.name != "nt":
                raise ConsentError("WINDOWS_REQUIRED")
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            user32.MessageBoxW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
            user32.MessageBoxW.restype = ctypes.c_int
            show = user32.MessageBoxW
        # No default on "Có": keyboard Enter alone declines the request.
        answer = show(None, plan["summary"], TITLE, 0x4 | 0x100 | 0x30)
        if answer != 6:
            return False
        service.request("approve_plan", plan_id=plan_id, version=plan["version"])
        return True
    finally:
        if own:
            service.close()


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int), ("hInstApp", wintypes.HANDLE), ("lpIDList", ctypes.c_void_p),
                ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HANDLE),
                ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]


def protected_helper() -> tuple[Path, Path]:
    # The tray runs from the portable install, so the helper's home comes from the
    # service registration, which only an administrator can have set.
    version = active_version() or registered_version()
    if version is None:
        raise ConsentError("INSTALL_INTEGRITY")
    expected = installed_paths(version.name).version
    if version.resolve(strict=True) != expected.resolve(strict=True):
        raise ConsentError("INSTALL_INTEGRITY")
    exe = version / "pythonw.exe"
    if not exe.is_file() or exe.is_symlink():
        raise ConsentError("INSTALL_INTEGRITY")
    return exe, version


def launch_consent(plan_id: str, *, timeout_ms: int = 150_000) -> bool:
    plan_id = validate_plan_id(plan_id)
    if os.name != "nt":
        raise ConsentError("WINDOWS_REQUIRED")
    exe, version = protected_helper()
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.GetExitCodeProcess.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40
    info.lpVerb = "runas"
    info.lpFile = str(exe)
    info.lpParameters = f"-I -B -m sentinel.service.consent --plan-id {plan_id}"
    info.lpDirectory = str(version)
    info.nShow = 1
    if not shell.ShellExecuteExW(ctypes.byref(info)):
        code = ctypes.get_last_error()
        if code == ERROR_CANCELLED:
            return False
        raise OSError(code, "ShellExecuteExW")
    try:
        wait = k32.WaitForSingleObject(info.hProcess, min(max(timeout_ms, 1), 300_000))
        if wait == WAIT_TIMEOUT:
            raise ConsentError("CONSENT_TIMEOUT")
        if wait != WAIT_OBJECT_0:
            raise OSError(ctypes.get_last_error(), "WaitForSingleObject")
        exit_code = wintypes.DWORD()
        if not k32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code)):
            raise OSError(ctypes.get_last_error(), "GetExitCodeProcess")
        return exit_code.value == 0
    finally:
        if info.hProcess:
            k32.CloseHandle(info.hProcess)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-id", required=True)
    args = parser.parse_args()
    return 0 if confirm(args.plan_id) else 1


if __name__ == "__main__":
    raise SystemExit(main())
