"""Windows service shell around ServiceCore (R13b P1: own ctypes SCM shell).

`ServiceHost` holds the state logic and talks to the Service Control Manager
through a small injected interface, so start/stop/preshutdown behaviour is
tested unelevated with a fake SCM. `run_as_service()` wires the real SCM via
ctypes; installing and starting the service is the owner's elevated step.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from typing import Protocol

log = logging.getLogger(__name__)

SERVICE_NAME = "SentinelGuard"

# winsvc.h
SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_STOPPED, SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_RUNNING = 1, 2, 3, 4
SERVICE_ACCEPT_STOP = 0x1
SERVICE_ACCEPT_PRESHUTDOWN = 0x100
SERVICE_CONTROL_STOP = 0x1
SERVICE_CONTROL_INTERROGATE = 0x4
SERVICE_CONTROL_PRESHUTDOWN = 0xF
NO_ERROR = 0
ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_SERVICE_SPECIFIC_ERROR = 1066
# dwServiceSpecificExitCode: without one SCM can only show a bare 1066.
EXIT_START_FAILED, EXIT_BARRIER_OPEN = 1, 2

STOP_WAIT_HINT_MS = 10_000
# How long a stop waits for an automatic action that already started (the
# action barrier, RT-018 / R11 invariant 11). Past this the process has to go
# (Windows is shutting down) and the stop is reported as failed, not clean; the
# next start recovers from the action journal.
STOP_BARRIER_SECONDS = 25.0
# SCM treats a checkpoint that stops advancing as a hung service.
STOP_SLICE_SECONDS = 5.0


class Scm(Protocol):
    def set_status(self, state: int, *, accepted: int, exit_code: int, checkpoint: int, wait_hint_ms: int,
                   service_code: int = 0) -> None: ...


class Service(Protocol):
    """What the host runs: start listening, stop (True when the action barrier
    closed; False to be asked again, so it must be safe to call repeatedly)."""

    def start(self) -> None: ...
    def stop(self, timeout: float) -> bool: ...


class ServiceHost:
    def __init__(self, service: Service, scm: Scm) -> None:
        self.service = service
        self.scm = scm
        self.state = SERVICE_STOPPED
        self._checkpoint = 0
        self._stop_requested = threading.Event()
        self._lock = threading.Lock()
        self.barrier_closed: bool | None = None

    def _report(self, state: int, *, exit_code: int = NO_ERROR, wait_hint_ms: int = 0, service_code: int = 0) -> None:
        with self._lock:
            self.state = state
            pending = state in (SERVICE_START_PENDING, SERVICE_STOP_PENDING)
            self._checkpoint = self._checkpoint + 1 if pending else 0
            # Stop/preshutdown are accepted only while running: a stop that
            # arrives during start-up waits until start-up has finished.
            accepted = (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN) if state == SERVICE_RUNNING else 0
            self.scm.set_status(state, accepted=accepted, exit_code=exit_code, checkpoint=self._checkpoint,
                                wait_hint_ms=wait_hint_ms, service_code=service_code)

    def control(self, code: int) -> int:
        """HandlerEx: runs on the SCM's thread, so it only signals."""
        if code in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_PRESHUTDOWN):
            if self.state == SERVICE_RUNNING:
                self._report(SERVICE_STOP_PENDING, wait_hint_ms=STOP_WAIT_HINT_MS)
                self._stop_requested.set()
            return NO_ERROR
        if code == SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR
        return ERROR_CALL_NOT_IMPLEMENTED

    def run(self) -> None:
        """ServiceMain body: start, wait for a stop control, stop behind the barrier."""
        self._report(SERVICE_START_PENDING, wait_hint_ms=STOP_WAIT_HINT_MS)
        try:
            self.service.start()
        except Exception:
            log.exception("service start failed")
            self._report(SERVICE_STOPPED, exit_code=ERROR_SERVICE_SPECIFIC_ERROR, service_code=EXIT_START_FAILED)
            return
        self._report(SERVICE_RUNNING)
        self._stop_requested.wait()
        self.barrier_closed = self._close_barrier()
        # A clean "stopped" is published only after the action barrier (R11 inv. 11).
        if self.barrier_closed:
            self._report(SERVICE_STOPPED)
        else:
            log.error("an automatic action was still running when the service had to stop")
            self._report(SERVICE_STOPPED, exit_code=ERROR_SERVICE_SPECIFIC_ERROR, service_code=EXIT_BARRIER_OPEN)

    def _close_barrier(self) -> bool:
        deadline = time.monotonic() + STOP_BARRIER_SECONDS
        while True:
            try:
                if self.service.stop(max(0.0, min(STOP_SLICE_SECONDS, deadline - time.monotonic()))):
                    return True
            except Exception:
                log.exception("service stop failed")
                return False
            if time.monotonic() >= deadline:
                return False
            self._report(SERVICE_STOP_PENDING, wait_hint_ms=STOP_WAIT_HINT_MS)


# -- real SCM via ctypes (Windows only; exercised by the owner's elevated script)


def run_as_service(make_service: Callable[[], Service], name: str = SERVICE_NAME) -> None:
    if os.name != "nt":
        raise OSError("Windows services need Windows")
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)

    class SERVICE_STATUS(ctypes.Structure):
        _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                    ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                    ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                    ("dwWaitHint", wintypes.DWORD)]

    HANDLER_EX = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p)
    SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))

    class SERVICE_TABLE_ENTRY(ctypes.Structure):
        _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", SERVICE_MAIN)]

    advapi.RegisterServiceCtrlHandlerExW.restype = ctypes.c_void_p
    advapi.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, HANDLER_EX, ctypes.c_void_p]
    advapi.SetServiceStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(SERVICE_STATUS)]
    advapi.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRY)]

    class RealScm:
        def __init__(self, handle: int) -> None:
            self.handle = handle

        def set_status(self, state: int, *, accepted: int, exit_code: int, checkpoint: int, wait_hint_ms: int,
                       service_code: int = 0) -> None:
            status = SERVICE_STATUS(SERVICE_WIN32_OWN_PROCESS, state, accepted,
                                    exit_code, service_code, checkpoint, wait_hint_ms)
            if not advapi.SetServiceStatus(self.handle, ctypes.byref(status)):
                log.error("SetServiceStatus failed (Windows error %d)", ctypes.get_last_error())

    holder: dict[str, ServiceHost] = {}

    def handler(control: int, event_type: int, event_data: int, context: int) -> int:
        host = holder.get("host")
        return host.control(control) if host else ERROR_CALL_NOT_IMPLEMENTED

    handler_fn = HANDLER_EX(handler)  # kept referenced for the process lifetime

    def service_main(argc: int, argv: object) -> None:
        handle = advapi.RegisterServiceCtrlHandlerExW(name, handler_fn, None)
        if not handle:
            log.error("RegisterServiceCtrlHandlerEx failed (Windows error %d)", ctypes.get_last_error())
            return
        host = ServiceHost(make_service(), RealScm(handle))
        holder["host"] = host
        host.run()

    main_fn = SERVICE_MAIN(service_main)
    table = (SERVICE_TABLE_ENTRY * 2)(SERVICE_TABLE_ENTRY(name, main_fn), SERVICE_TABLE_ENTRY(None, SERVICE_MAIN()))
    if not advapi.StartServiceCtrlDispatcherW(table):
        raise OSError(ctypes.get_last_error(), "StartServiceCtrlDispatcher failed (not started by the SCM?)")
