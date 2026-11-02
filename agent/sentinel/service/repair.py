"""Cleaning up what quarantine alone cannot (A6).

A running program holds its file, so it cannot be quarantined, and a Run value
keeps pointing at what was removed. A repair is built, shown to the user, and
only then carried out, re-checking every target first: the plan says what was
agreed to, never what is true now. Stopping a program cannot be undone; a removed
autostart value is journalled and comes back if the file is restored.
"""

from __future__ import annotations

import ctypes
import logging
import ntpath
import os
import time
import uuid
from collections.abc import Callable, Iterator
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any

from .. import config, quarantine
from ..db import Database
from ..gate_v2 import identity, scope, winfile
from .procwatch import ProcessKey, windows_resolve, windows_snapshot

log = logging.getLogger(__name__)

PROCESS_TERMINATE, PROCESS_QUERY_LIMITED_INFORMATION, SYNCHRONIZE = 0x1, 0x1000, 0x00100000
WAIT_OBJECT_0 = 0
STOP_WAIT_MS = 5000
RELEASE_SECONDS = 5.0  # the file stays locked for a moment after its process ends
FIRST_USER_PID = 8


def shown(text: str) -> str:
    """Text from a file name or a page, safe to put in a confirmation.

    Direction overrides and control characters are how a name is made to read
    as something else in the one prompt the user trusts.
    """
    return _plain(text)[:300]


def _plain(text: str) -> str:
    return " ".join("".join(c for c in text if c.isprintable()).split())


def shown_path(path: str) -> str:
    """Both ends of a path: padding the middle is how a prompt is made to hide the end."""
    text = _plain(path)
    return text if len(text) <= 160 else f"{text[:80]} … {text[-70:]}"


class RepairError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class Process:
    pid: int
    creation_time: int
    image: str


@dataclass(frozen=True)
class RunValue:
    hive: str  # HKLM, HKCU, or a user's SID
    key: str
    view: int
    name: str
    data: str
    kind: int


@dataclass(frozen=True)
class Repair:
    repair_id: str
    path: str
    sha256: str
    processes: tuple[Process, ...]
    autostart: tuple[RunValue, ...]


def _same_file(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return winfile.same_path(a, b)


def find_processes(path: str, *, snapshot: Callable[[], Any] = windows_snapshot,
                   resolve: Callable[[ProcessKey], tuple[str, tuple[int, int]]] = windows_resolve) -> tuple[Process, ...]:
    found = []
    for key in snapshot().keys:
        try:
            image, _ = resolve(key)
        except OSError:
            continue
        if _same_file(image, path):
            found.append(Process(key.pid, key.creation_time, image))
    return tuple(found)


def _hives(reg: Any) -> Iterator[tuple[str, Any, str]]:
    yield "HKLM", reg.HKEY_LOCAL_MACHINE, ""
    yield "HKCU", reg.HKEY_CURRENT_USER, ""
    try:
        index = 0
        while True:
            sid = reg.EnumKey(reg.HKEY_USERS, index)
            index += 1
            if sid.startswith("S-1-5-21-") and not sid.endswith("_Classes"):
                yield sid, reg.HKEY_USERS, sid + "\\"
    except OSError:
        return


def find_autostart(path: str, reg: Any = None) -> tuple[RunValue, ...]:
    if reg is None:
        if os.name != "nt":
            return ()
        import winreg as reg
    from ..watcher import RUN_KEYS, command_files

    try:
        profiles = dict(scope._profiles(reg))
    except OSError:
        profiles = {}
    found: dict[tuple[str, str, int, str], RunValue] = {}
    for hive, root, prefix in _hives(reg):
        for key in RUN_KEYS:
            for view in (reg.KEY_WOW64_64KEY, reg.KEY_WOW64_32KEY):
                try:
                    with reg.OpenKey(root, prefix + key, 0, reg.KEY_READ | view) as opened:
                        index = 0
                        while True:
                            try:
                                name, data, kind = reg.EnumValue(opened, index)
                            except OSError:
                                break
                            index += 1
                            command = scope.for_profile(str(data), profiles.get(hive))
                            if any(_same_file(f, path) for f in command_files(command)):
                                found[(hive, key, view, name)] = RunValue(hive, key, view, name, str(data), kind)
                except OSError:
                    continue  # a missing or denied key holds nothing this repair can change
    return tuple(found.values())


def plan(path: str, sha256: str, *, snapshot: Callable[[], Any] = windows_snapshot,
         resolve: Callable[[ProcessKey], tuple[str, tuple[int, int]]] = windows_resolve, reg: Any = None) -> Repair:
    if winfile.is_protected(path):
        raise RepairError("PROTECTED_PATH", path)
    return Repair(uuid.uuid4().hex, path, sha256, find_processes(path, snapshot=snapshot, resolve=resolve),
                  find_autostart(path, reg))


def describe(repair: Repair) -> str:
    lines = [f"Xử lý {shown_path(repair.path)}, SHA-256 {repair.sha256[:16]}:"]
    if repair.processes:
        lines.append(f"Dừng {len(repair.processes)} chương trình đang chạy từ tệp này (không hoàn tác được).")
    lines.append("Cách ly tệp.")
    if repair.autostart:
        names = ", ".join(shown(v.name) for v in repair.autostart[:4])
        lines.append(f"Gỡ tự khởi động: {names}. Mục này sẽ quay lại nếu bạn khôi phục tệp.")
    return " ".join(lines)


if os.name == "nt":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.TerminateProcess.restype = wintypes.BOOL
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]


def stop_process(process: Process) -> bool:
    """False if it was gone already. Refuses a pid that now belongs to another program."""
    if process.pid < FIRST_USER_PID or process.pid == os.getpid():
        raise RepairError("REFUSED_PROCESS", str(process.pid))
    handle = _k32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, process.pid)
    if not handle:
        return False
    try:
        created, exited, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
        if not _k32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                    ctypes.byref(kernel_time), ctypes.byref(user_time)):
            raise RepairError("STOP_FAILED", str(process.pid))
        if ((created.dwHighDateTime << 32) | created.dwLowDateTime) != process.creation_time:
            return False  # the same number, another program
        if not _k32.TerminateProcess(handle, 1):
            raise RepairError("STOP_FAILED", str(process.pid))
        if _k32.WaitForSingleObject(handle, STOP_WAIT_MS) != WAIT_OBJECT_0:
            raise RepairError("STOP_FAILED", str(process.pid))
        return True
    finally:
        _k32.CloseHandle(handle)


def _root(reg: Any, value: RunValue) -> tuple[Any, str]:
    if value.hive == "HKLM":
        return reg.HKEY_LOCAL_MACHINE, value.key
    if value.hive == "HKCU":
        return reg.HKEY_CURRENT_USER, value.key
    return reg.HKEY_USERS, f"{value.hive}\\{value.key}"


def remove_value(value: RunValue, reg: Any) -> bool:
    """Only the value that was shown: anything else under that name is not ours to delete."""
    root, key = _root(reg, value)
    with reg.OpenKey(root, key, 0, reg.KEY_READ | reg.KEY_SET_VALUE | value.view) as opened:
        data, _ = reg.QueryValueEx(opened, value.name)
        if str(data) != value.data:
            return False
        reg.DeleteValue(opened, value.name)
    return True


def _release(path: str) -> None:
    deadline = time.monotonic() + RELEASE_SECONDS
    while time.monotonic() < deadline:
        try:
            winfile.open_target(path).close()
            return
        except winfile.TargetError:
            time.sleep(0.05)


def execute(db: Database, repair: Repair, verdict: dict[str, Any], *, reg: Any = None) -> dict[str, Any]:
    if reg is None and os.name == "nt":
        import winreg as reg
    found = identity.measure(repair.path, max_bytes=config.MAX_SCAN_BYTES)
    # The file is the reason for all of this; a different file gets no process stopped.
    if not found.ok or found.identity is None or found.identity.sha256 != repair.sha256:
        raise RepairError("CHANGED", repair.path)
    stopped = 0
    for process in repair.processes:
        if not _same_file(process.image, repair.path):
            raise RepairError("CHANGED", process.image)
        stopped += 1 if stop_process(process) else 0
    _release(repair.path)
    try:
        qid = quarantine.quarantine(db, repair.path, {**verdict, "sha256": repair.sha256})
    except quarantine.QuarantineError as e:
        raise RepairError(e.code, repair.path) from e
    removed = left = 0
    for value in repair.autostart:
        try:
            if remove_value(value, reg):
                db.add_repair_undo(qid, value.hive, value.key, value.view, value.name, value.data, value.kind)
                removed += 1
            else:
                left += 1
        except FileNotFoundError:
            pass  # HKCU is one key in both views, so it was seen twice and is gone now
        except OSError:
            log.warning("could not remove autostart value %s", value.name)
            left += 1
    return {"quarantine_id": qid, "stopped": stopped, "autostart_removed": removed, "autostart_left": left}


def undo(db: Database, quarantine_id: str, *, reg: Any = None) -> int:
    """After a restore: what the repair took away goes back to where it was."""
    if reg is None:
        if os.name != "nt":
            return 0
        import winreg as reg
    back = 0
    for row in db.repair_undos(quarantine_id):
        value = RunValue(row["hive"], row["key"], int(row["view"]), row["name"], row["data"], int(row["kind"]))
        root, key = _root(reg, value)
        try:
            with reg.OpenKey(root, key, 0, reg.KEY_SET_VALUE | value.view) as opened:
                reg.SetValueEx(opened, value.name, 0, value.kind, value.data)
            back += 1
        except OSError:
            log.warning("could not put back autostart value %s", ntpath.basename(value.name))
    db.clear_repair_undos(quarantine_id)
    return back
