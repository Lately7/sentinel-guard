"""Bind a Windows TCP connection to the process at its server end."""

from __future__ import annotations

import os
import socket
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class ExpectedDaemon:
    pid: int
    creation_time_100ns: int
    image_path: str


def connected_server_pid(connection: socket.socket) -> int | None:
    if sys.platform != "win32":
        return None
    import ctypes

    local_ip, local_port = connection.getsockname()[:2]
    peer_ip, peer_port = connection.getpeername()[:2]
    if ":" in local_ip or ":" in peer_ip:
        return None
    api = ctypes.WinDLL("iphlpapi", use_last_error=True).GetExtendedTcpTable
    api.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_int,
                    ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    api.restype = ctypes.c_ulong
    size = ctypes.c_ulong()
    api(None, ctypes.byref(size), False, socket.AF_INET, 5, 0)
    if size.value < 4 or size.value > 16 * 1024 * 1024:
        return None
    buffer = ctypes.create_string_buffer(size.value)
    if api(buffer, ctypes.byref(size), False, socket.AF_INET, 5, 0) != 0:
        return None
    raw = buffer.raw[:size.value]
    count = int.from_bytes(raw[:4], "little")
    if count > (len(raw) - 4) // 24:
        return None
    # MIB_TCPROW_OWNER_PID: state, local address/port, remote address/port, PID.
    for index in range(count):
        row = raw[4 + index * 24:4 + (index + 1) * 24]
        if (int.from_bytes(row[:4], "little") == 5 and
            socket.inet_ntoa(row[4:8]) == peer_ip and
            int.from_bytes(row[8:10], "big") == peer_port and
            socket.inet_ntoa(row[12:16]) == local_ip and
            int.from_bytes(row[16:18], "big") == local_port):
            return int.from_bytes(row[20:24], "little")
    return None


def verify_connected_daemon(connection: socket.socket, expected: ExpectedDaemon | None) -> bool:
    if sys.platform != "win32" or expected is None:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        if connected_server_pid(connection) != expected.pid:
            return False
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                       wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x1000, False, expected.pid)
        if not handle:
            return False
        try:
            creation = ctypes.c_ulonglong()
            other = (ctypes.c_ulonglong * 3)()
            if not kernel.GetProcessTimes(handle, ctypes.byref(creation),
                                          ctypes.byref(other, 0), ctypes.byref(other, 8),
                                          ctypes.byref(other, 16)):
                return False
            path = ctypes.create_unicode_buffer(32768)
            length = wintypes.DWORD(len(path))
            if not kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(length)):
                return False
            return (creation.value == expected.creation_time_100ns and
                    os.path.normcase(os.path.abspath(path.value)) ==
                    os.path.normcase(os.path.abspath(expected.image_path)))
        finally:
            kernel.CloseHandle(handle)
    except (OSError, ValueError, AttributeError):
        return False
