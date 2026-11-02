"""Bounded NTFS USN parsing and resumable journal reads (A5).

The journal is how the service catches up after the file watcher overflowed or
nothing was running. Every way of losing the thread (journal replaced or
disabled, cursor overrun, access denied) is a typed gap that demands
reconciliation, because missed changes must not read as no changes.
"""

from __future__ import annotations

import ctypes
import os
import struct
import time
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from typing import Protocol

FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_READ_USN_JOURNAL = 0x000900BB
USN_REASON_DATA_OVERWRITE, USN_REASON_DATA_EXTEND, USN_REASON_DATA_TRUNCATION = 0x1, 0x2, 0x4
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_RENAME_OLD_NAME = 0x00001000
USN_REASON_RENAME_NEW_NAME = 0x00002000
USN_REASON_HARD_LINK_CHANGE = 0x00010000
USN_REASON_REPARSE_POINT_CHANGE = 0x00100000
USN_REASON_STREAM_CHANGE = 0x00200000
USN_REASON_CLOSE = 0x80000000
CHANGED = (USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND | USN_REASON_DATA_TRUNCATION | USN_REASON_FILE_CREATE |
           USN_REASON_RENAME_NEW_NAME | USN_REASON_HARD_LINK_CHANGE | USN_REASON_STREAM_CHANGE |
           USN_REASON_REPARSE_POINT_CHANGE)
ERROR_ACCESS_DENIED = 5
ERROR_JOURNAL_DELETE_IN_PROGRESS = 1178
ERROR_JOURNAL_NOT_ACTIVE = 1179
ERROR_JOURNAL_ENTRY_DELETED = 1181
MIN_RECORD = 60
JOURNAL_DATA_BYTES = 56


@dataclass(frozen=True)
class UsnRecord:
    version: int
    file_ref: bytes
    parent_ref: bytes
    usn: int
    reason: int
    name: str


@dataclass(frozen=True)
class JournalData:
    journal_id: int
    first_usn: int
    next_usn: int
    lowest_valid_usn: int
    max_usn: int
    maximum_size: int
    allocation_delta: int


@dataclass(frozen=True)
class JournalCursor:
    volume: str
    journal_id: int
    next_usn: int
    checkpoint: float


@dataclass(frozen=True)
class JournalGap:
    reason: str
    reconciliation_required: bool = True


@dataclass(frozen=True)
class ResolvedChange:
    record: UsnRecord
    path: str


@dataclass(frozen=True)
class Batch:
    records: tuple[ResolvedChange, ...] = ()
    cursor: JournalCursor | None = None
    gaps: tuple[JournalGap, ...] = ()
    unresolved: int = 0  # changed files with no path now: most were replaced or removed since


class CursorStore(Protocol):
    def load(self, volume: str) -> JournalCursor | None: ...
    def save(self, cursor: JournalCursor) -> None: ...


class Device(Protocol):
    def control(self, code: int, data: bytes, output_size: int) -> bytes: ...


def parse_journal_data(data: bytes) -> JournalData | None:
    if len(data) < JOURNAL_DATA_BYTES:
        return None
    values = struct.unpack_from("<QQQQQQQ", data)
    if values[2] < values[1] or values[4] < values[2]:
        return None
    return JournalData(*values)


def parse_record(data: bytes) -> UsnRecord | None:
    if len(data) < MIN_RECORD:
        return None
    length, major, minor = struct.unpack_from("<IHH", data)
    if length > len(data) or length < MIN_RECORD or major not in (2, 3) or minor > 9:
        return None
    header = MIN_RECORD if major == 2 else 76
    if length < header:
        return None
    ref_size = 8 if major == 2 else 16
    file_ref = data[8:8 + ref_size]
    parent_ref = data[8 + ref_size:8 + 2 * ref_size]
    usn_offset = 24 if major == 2 else 40
    usn = struct.unpack_from("<q", data, usn_offset)[0]
    reason = struct.unpack_from("<I", data, usn_offset + 16)[0]
    name_length, name_offset = struct.unpack_from("<HH", data, header - 4)
    if (usn < 0 or name_length % 2 or name_offset < header or
            name_offset > length or name_length > length - name_offset or name_length > 32768):
        return None
    try:
        name = data[name_offset:name_offset + name_length].decode("utf-16-le", "strict")
    except UnicodeError:
        return None
    return UsnRecord(major, file_ref, parent_ref, usn, reason, name)


def parse_batch(data: bytes) -> tuple[int, tuple[UsnRecord, ...], JournalGap | None]:
    """Bounded by the buffer: each record is at least MIN_RECORD bytes."""
    if len(data) < 8:
        return 0, (), JournalGap("malformed_batch")
    next_usn = struct.unpack_from("<q", data)[0]
    if next_usn < 0:
        return 0, (), JournalGap("malformed_batch")
    records: list[UsnRecord] = []
    offset = 8
    while offset < len(data):
        if len(data) - offset < 4:
            return next_usn, tuple(records), JournalGap("malformed_record")
        length = struct.unpack_from("<I", data, offset)[0]
        if length < MIN_RECORD or length > len(data) - offset:
            return next_usn, tuple(records), JournalGap("malformed_record")
        record = parse_record(data[offset:offset + length])
        if record is None:
            return next_usn, tuple(records), JournalGap("malformed_record")
        records.append(record)
        offset += length
    return next_usn, tuple(records), None


def _error_reason(exc: OSError) -> str:
    code = getattr(exc, "winerror", None) or exc.errno
    if code == ERROR_ACCESS_DENIED:
        return "access_denied"
    if code in (ERROR_JOURNAL_NOT_ACTIVE, ERROR_JOURNAL_DELETE_IN_PROGRESS):
        return "journal_not_active"
    if code == ERROR_JOURNAL_ENTRY_DELETED:
        return "wrapped_cursor"
    return "device_error"


def _query(device: Device) -> JournalData | JournalGap:
    try:
        info = parse_journal_data(device.control(FSCTL_QUERY_USN_JOURNAL, b"", JOURNAL_DATA_BYTES))
    except OSError as exc:
        return JournalGap(_error_reason(exc))
    return info if info is not None else JournalGap("malformed_journal_data")


def reset_cursor(volume: str, device: Device, store: CursorStore,
                 clock: Callable[[], float] = time.time) -> JournalGap | None:
    """Starts over at the journal's end, once whatever was missed has been reconciled."""
    info = _query(device)
    if isinstance(info, JournalGap):
        return info
    try:
        store.save(JournalCursor(volume, info.journal_id, info.next_usn, clock()))
    except OSError:
        return JournalGap("cursor_store_error")
    return None


def read_batch(volume: str, device: Device, store: CursorStore,
               resolver: Callable[[UsnRecord], str | None], *,
               max_bytes: int = 1 << 20, clock: Callable[[], float] = time.time) -> Batch:
    if max_bytes < 80:
        raise ValueError("bounds")
    info = _query(device)
    if isinstance(info, JournalGap):
        return Batch(gaps=(info,))
    try:
        cursor = store.load(volume)
    except OSError:
        return Batch(gaps=(JournalGap("cursor_store_error"),))
    if cursor is None:
        # Nothing before this moment was seen: the first start is a gap as well.
        return Batch(gaps=(JournalGap("no_cursor"),))
    if cursor.journal_id != info.journal_id:
        return Batch(gaps=(JournalGap("journal_id_changed"),))
    if cursor.next_usn < info.lowest_valid_usn or cursor.next_usn > info.next_usn:
        return Batch(gaps=(JournalGap("wrapped_cursor"),))
    # Only on close: one record per file, once it stopped changing, is what a
    # scan wants, and it cuts the volume of records by an order of magnitude.
    request = struct.pack("<qIIQQQ", cursor.next_usn, 0xFFFFFFFF, 1, 0, 0, info.journal_id)
    try:
        raw = device.control(FSCTL_READ_USN_JOURNAL, request, max_bytes)
    except OSError as exc:
        return Batch(gaps=(JournalGap(_error_reason(exc)),))
    next_usn, records, gap = parse_batch(raw)
    if gap:
        return Batch(gaps=(gap,))
    if next_usn < cursor.next_usn:
        return Batch(gaps=(JournalGap("wrapped_cursor"),))
    resolved: list[ResolvedChange] = []
    unresolved = 0
    for record in records:
        if not record.reason & CHANGED or record.reason & USN_REASON_FILE_DELETE:
            continue
        try:
            path = resolver(record)
        except OSError:
            path = None
        if path is None:
            unresolved += 1
        else:
            resolved.append(ResolvedChange(record, path))
    advanced = JournalCursor(volume, info.journal_id, next_usn, clock())
    try:
        store.save(advanced)
    except OSError:
        return Batch(tuple(resolved), None, (JournalGap("cursor_store_error"),), unresolved)
    return Batch(tuple(resolved), advanced, (), unresolved)


class FILE_ID_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("Type", ctypes.c_int), ("FileId", ctypes.c_ubyte * 16)]


if os.name == "nt":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                     ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    _k32.DeviceIoControl.restype = wintypes.BOOL
    _k32.OpenFileById.restype = wintypes.HANDLE
    _k32.OpenFileById.argtypes = [wintypes.HANDLE, ctypes.POINTER(FILE_ID_DESCRIPTOR), wintypes.DWORD,
                                  wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    _k32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _k32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]

GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, OPEN_EXISTING = 0x80000000, 0x80, 0x7, 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE = wintypes.HANDLE(-1).value


class WindowsVolume:
    """The volume itself where this account may open it, its root folder otherwise.

    The root folder is enough to ask about the journal, not to read it; that
    shows up as a typed access_denied gap instead of a silent nothing.
    """

    def __init__(self, root: str) -> None:
        if os.name != "nt":
            raise OSError("Windows only")
        self.root = root
        self.handle = _k32.CreateFileW("\\\\.\\" + root.rstrip("\\"), GENERIC_READ, FILE_SHARE_ALL, None,
                                       OPEN_EXISTING, 0, None)
        if self.handle in (None, INVALID_HANDLE):
            self.handle = _k32.CreateFileW(root, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, None, OPEN_EXISTING,
                                           FILE_FLAG_BACKUP_SEMANTICS, None)
        if self.handle in (None, INVALID_HANDLE):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self.handle:
            _k32.CloseHandle(self.handle)
            self.handle = 0

    def control(self, code: int, data: bytes, output_size: int) -> bytes:
        out = ctypes.create_string_buffer(output_size)
        returned = wintypes.DWORD()
        source = ctypes.create_string_buffer(data, len(data)) if data else None
        if not _k32.DeviceIoControl(self.handle, code, source, len(data), out, output_size,
                                    ctypes.byref(returned), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return out.raw[:returned.value]

    def resolve(self, record: UsnRecord) -> str | None:
        """The file's path now, opened by id: the name in the record may be old already."""
        descriptor = FILE_ID_DESCRIPTOR()
        descriptor.dwSize = ctypes.sizeof(descriptor)
        descriptor.Type = 0 if len(record.file_ref) == 8 else 2  # FileIdType, ExtendedFileIdType
        ctypes.memmove(descriptor.FileId, record.file_ref, len(record.file_ref))
        opened = _k32.OpenFileById(self.handle, ctypes.byref(descriptor), FILE_READ_ATTRIBUTES, FILE_SHARE_ALL,
                                   None, FILE_FLAG_BACKUP_SEMANTICS)
        if opened in (None, INVALID_HANDLE):
            return None
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            length = _k32.GetFinalPathNameByHandleW(opened, buffer, len(buffer), 0)
            if not length or length >= len(buffer):
                return None
            return buffer.value[4:] if buffer.value.startswith("\\\\?\\") else buffer.value
        finally:
            _k32.CloseHandle(opened)
