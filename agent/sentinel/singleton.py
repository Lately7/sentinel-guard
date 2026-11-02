"""Cross-process coordination with Windows named kernel objects.

Named mutexes are released by the OS when a process dies, so a crash can
never leave a stale lock behind (unlike lock files).
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable

_ERROR_ALREADY_EXISTS = 183
_WAIT_OBJECT_0 = 0
_WAIT_ABANDONED = 0x80
_INFINITE = 0xFFFFFFFF

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    _k32.CreateMutexW.restype = wintypes.HANDLE
    _k32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    _k32.CreateEventW.restype = wintypes.HANDLE
    _k32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    _k32.OpenEventW.restype = wintypes.HANDLE
    _k32.SetEvent.argtypes = [wintypes.HANDLE]
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.ReleaseMutex.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]

APP_MUTEX = "Local\\SentinelGuard.Tray"
SHOW_EVENT = "Local\\SentinelGuard.ShowDashboard"
FEEDS_MUTEX = "Local\\SentinelGuard.FeedUpdate"


class NamedLock:
    """Non-blocking cross-process lock: `with NamedLock(name) as got: if got: ...`."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._handle = None
        self.acquired = False

    def acquire(self, timeout_ms: int = 0) -> bool:
        if os.name != "nt":
            self.acquired = True
            return True
        self._handle = _k32.CreateMutexW(None, False, self.name)
        if not self._handle:
            raise OSError(ctypes.get_last_error(), "CreateMutexW failed")
        r = _k32.WaitForSingleObject(self._handle, timeout_ms)
        # An abandoned mutex means the previous owner crashed: we own it now.
        self.acquired = r in (_WAIT_OBJECT_0, _WAIT_ABANDONED)
        return self.acquired

    def release(self) -> None:
        if os.name == "nt" and self._handle:
            if self.acquired:
                _k32.ReleaseMutex(self._handle)
            _k32.CloseHandle(self._handle)
            self._handle = None
        self.acquired = False

    def __enter__(self) -> bool:
        return self.acquire()

    def __exit__(self, *exc: object) -> None:
        self.release()


class AppInstance:
    """Single tray instance. A second launch asks the first one to show its window."""

    def __init__(self) -> None:
        self.lock = NamedLock(APP_MUTEX)

    def claim(self) -> bool:
        return self.lock.acquire()

    def signal_existing(self) -> None:
        if os.name != "nt":
            return
        h = _k32.OpenEventW(0x0002, False, SHOW_EVENT)  # EVENT_MODIFY_STATE
        if h:
            _k32.SetEvent(h)
            _k32.CloseHandle(h)

    def on_show_request(self, callback: Callable[[], None]) -> None:
        if os.name != "nt":
            return
        h = _k32.CreateEventW(None, False, False, SHOW_EVENT)  # auto-reset

        def wait() -> None:
            while True:
                if _k32.WaitForSingleObject(h, _INFINITE) == _WAIT_OBJECT_0:
                    callback()

        threading.Thread(target=wait, daemon=True, name="show-request").start()
