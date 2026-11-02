"""Bounded, handle-based measurement of one file generation.

On non-Windows hosts canonical paths use realpath; Windows uses the opened
handle so a later path lookup cannot silently change the measured target.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import stat
from dataclasses import dataclass
from typing import Callable

from .contract import CancellationToken, ContractError, FileIdentity

CHUNK_SIZE = 1024 * 1024

if os.name == "nt":
    import msvcrt

    class FileBasicInfo(ctypes.Structure):
        _fields_ = [(name, ctypes.c_int64) for name in
                    ("creation", "access", "write", "change")] + [("attributes", ctypes.c_uint32)]

    _get_file_information = ctypes.windll.kernel32.GetFileInformationByHandleEx
    _get_file_information.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    _get_file_information.restype = ctypes.c_int
    _get_final_path = ctypes.windll.kernel32.GetFinalPathNameByHandleW
    _get_final_path.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    _get_final_path.restype = ctypes.c_uint32


@dataclass(frozen=True)
class IdentityResult:
    identity: FileIdentity | None
    code: str

    @property
    def ok(self) -> bool:
        return self.identity is not None and self.code == "OK"


def _cancelled(cancel: CancellationToken | None) -> bool:
    return cancel is not None and cancel.cancelled()


def _change_time(descriptor: int, info: os.stat_result) -> int:
    if os.name != "nt":
        return info.st_ctime_ns
    basic = FileBasicInfo()
    if not _get_file_information(msvcrt.get_osfhandle(descriptor), 0, ctypes.byref(basic), ctypes.sizeof(basic)):
        raise OSError("change time unavailable")
    return max(0, (basic.change - 116444736000000000) * 100)


def _generation(info: os.stat_result, change_time_ns: int) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, change_time_ns


def _final_path(descriptor: int, fallback: str) -> str:
    if os.name != "nt":
        return os.path.realpath(fallback)
    handle = msvcrt.get_osfhandle(descriptor)
    length = _get_final_path(handle, None, 0, 0)
    if not length or length > 32768:
        raise OSError("final path unavailable")
    buffer = ctypes.create_unicode_buffer(length + 1)
    written = _get_final_path(handle, buffer, len(buffer), 0)
    if not written or written >= len(buffer):
        raise OSError("final path unavailable")
    path = buffer.value
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    return path[4:] if path.startswith("\\\\?\\") else path


def measure(
    path: str, *, max_bytes: int = 512 * 1024 * 1024,
    cancel: CancellationToken | None = None,
    chunk_size: int = CHUNK_SIZE,
    between_chunks: Callable[[int], None] | None = None,
) -> IdentityResult:
    if max_bytes < 0 or chunk_size <= 0:
        raise ValueError("invalid measurement limit")
    if _cancelled(cancel):
        return IdentityResult(None, "CANCELLED")
    try:
        with open(path, "rb", buffering=0) as stream:
            before = os.fstat(stream.fileno())
            before_change = _change_time(stream.fileno(), before)
            if not stat.S_ISREG(before.st_mode):
                return IdentityResult(None, "NOT_REGULAR")
            if before.st_size > max_bytes:
                return IdentityResult(None, "TOO_LARGE")
            canonical = _final_path(stream.fileno(), path)
            digest = hashlib.sha256()
            count = 0
            while True:
                if _cancelled(cancel):
                    return IdentityResult(None, "CANCELLED")
                block = stream.read(min(chunk_size, max_bytes - count + 1))
                if not block:
                    break
                count += len(block)
                if count > max_bytes:
                    return IdentityResult(None, "TOO_LARGE")
                digest.update(block)
                if between_chunks is not None:
                    between_chunks(count)
            after = os.fstat(stream.fileno())
            after_change = _change_time(stream.fileno(), after)
            if _generation(before, before_change) != _generation(after, after_change) or count != after.st_size:
                return IdentityResult(None, "CHANGED")
            return IdentityResult(FileIdentity(
                canonical, after.st_dev, f"{after.st_ino:032x}", count,
                digest.hexdigest(), after_change, after.st_mtime_ns,
            ), "OK")
    except (OSError, ValueError, OverflowError, ContractError) as exc:
        if isinstance(exc, (IsADirectoryError, PermissionError)):
            try:
                if stat.S_ISDIR(os.stat(path).st_mode):
                    return IdentityResult(None, "NOT_REGULAR")
            except OSError:
                pass
        return IdentityResult(None, "UNREADABLE")


def measure_bytes(
    data: bytes, *, max_bytes: int = 512 * 1024 * 1024,
    cancel: CancellationToken | None = None, chunk_size: int = CHUNK_SIZE,
) -> IdentityResult:
    if max_bytes < 0 or chunk_size <= 0:
        raise ValueError("invalid measurement limit")
    if len(data) > max_bytes:
        return IdentityResult(None, "TOO_LARGE")
    digest = hashlib.sha256()
    for offset in range(0, len(data), chunk_size):
        if _cancelled(cancel):
            return IdentityResult(None, "CANCELLED")
        digest.update(memoryview(data)[offset:offset + chunk_size])
    if _cancelled(cancel):
        return IdentityResult(None, "CANCELLED")
    return IdentityResult(FileIdentity(None, None, None, len(data), digest.hexdigest(), None, None), "OK")


def revalidate(
    path: str, expected: FileIdentity, *, rehash: bool,
    max_bytes: int = 512 * 1024 * 1024,
    cancel: CancellationToken | None = None,
) -> IdentityResult:
    # Reopening is necessary for path consumers; a restored mtime can only be
    # defeated by comparing bytes from the newly opened generation.
    if not rehash:
        if _cancelled(cancel):
            return IdentityResult(None, "CANCELLED")
        try:
            with open(path, "rb", buffering=0) as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    return IdentityResult(None, "NOT_REGULAR")
                if info.st_size > max_bytes:
                    return IdentityResult(None, "TOO_LARGE")
                metadata = (info.st_dev, f"{info.st_ino:032x}", info.st_size,
                            info.st_mtime_ns, _change_time(stream.fileno(), info))
                expected_metadata = (expected.volume_serial, expected.file_id_hex,
                                     expected.size, expected.mtime_ns, expected.change_time_ns)
                return IdentityResult(expected if metadata == expected_metadata else None,
                                      "OK" if metadata == expected_metadata else "CHANGED")
        except (OSError, ValueError, OverflowError):
            return IdentityResult(None, "UNREADABLE")
    actual = measure(path, max_bytes=max_bytes, cancel=cancel)
    if not actual.ok:
        return actual
    assert actual.identity is not None
    observed = actual.identity
    if (observed.volume_serial, observed.file_id_hex, observed.size,
        observed.mtime_ns, observed.change_time_ns) != (
        expected.volume_serial, expected.file_id_hex, expected.size,
        expected.mtime_ns, expected.change_time_ns,
    ) or (rehash and observed.sha256 != expected.sha256):
        return IdentityResult(None, "CHANGED")
    return actual
