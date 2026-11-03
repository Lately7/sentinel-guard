"""One measured file generation and bounded, recorded reads for local adapters.

Bound adapters receive this object through ``scan_bound(request, identity,
cancel, reader)``. Legacy/path adapters retain ``scan(request, identity, cancel)``.
The owner closes the reader after all stages; adapters never reopen its path.
"""

from __future__ import annotations

import hashlib
import os
from typing import BinaryIO

from . import identity
from .contract import ByteRange, CancellationToken, FileIdentity
from .coverage import normalize_ranges

CHUNK = 1024 * 1024

if os.name == "nt":
    import ctypes
    import msvcrt

    _create_file = ctypes.windll.kernel32.CreateFileW
    _create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                             ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    _create_file.restype = ctypes.c_void_p
    _close_handle = ctypes.windll.kernel32.CloseHandle
    _close_handle.argtypes = [ctypes.c_void_p]


def _open_measured(path: str) -> BinaryIO:
    if os.name != "nt":
        return open(path, "rb", buffering=0)
    # OPEN_NO_RECALL: the main way into a scan must not download a cloud placeholder.
    # measure_stream reads the attributes first and stops before any content.
    handle = _create_file(path, 0x80000000, 0x1 | 0x4, None, 3, 0x80 | 0x00100000, None)
    if handle == ctypes.c_void_p(-1).value:
        code = ctypes.windll.kernel32.GetLastError()
        if code in (32, 33):
            raise ContentError("IN_USE")
        raise OSError(code, "CreateFileW failed", path)
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        _close_handle(handle)
        raise
    return os.fdopen(descriptor, "rb", buffering=0)


class ContentError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class BoundReader:
    def __init__(self, measured: FileIdentity, *, stream: BinaryIO | None = None,
                 data: bytes | None = None, resident_limit: int = 64 * 1024 * 1024) -> None:
        self.identity = measured
        self._stream = stream
        self._data = data
        self.resident_limit = resident_limit
        self._reads: list[ByteRange] = []
        # Core, JSON rules and YARA-X all read the same front of the file; the
        # generation check still runs, only the disk read and the copy are saved.
        self._last: tuple[int, int, bytes] | None = None

    @classmethod
    def measure_path(cls, path: str, *, max_bytes: int,
                     cancel: CancellationToken, resident_limit: int = 64 * 1024 * 1024) -> BoundReader:
        stream = _open_measured(path)
        try:
            result = identity.measure_stream(stream, path, max_bytes=max_bytes, cancel=cancel,
                                             ignore_times=os.name == "nt")
            if not result.ok:
                raise ContentError(result.code)
            assert result.identity is not None
            return cls(result.identity, stream=stream, resident_limit=resident_limit)
        except BaseException:
            stream.close()
            raise

    @classmethod
    def from_bytes(cls, data: bytes, measured: FileIdentity, *, resident_limit: int = 64 * 1024 * 1024) -> BoundReader:
        if len(data) != measured.size or hashlib.sha256(data).hexdigest() != measured.sha256:
            raise ContentError("CHANGED")
        return cls(measured, data=data, resident_limit=resident_limit)

    @classmethod
    def from_stream(cls, stream: BinaryIO, measured: FileIdentity, *, resident_limit: int = 64 * 1024 * 1024) -> BoundReader:
        """Accept a supplied read-only handle without taking ownership of it."""
        reader = cls(measured, stream=stream, resident_limit=resident_limit)
        reader._check()
        return reader

    def _check(self) -> None:
        if self._stream is None:
            return
        info = os.fstat(self._stream.fileno())
        actual = (info.st_dev, f"{info.st_ino:032x}", info.st_size)
        expected = (self.identity.volume_serial, self.identity.file_id_hex, self.identity.size)
        if os.name != "nt":  # no write-denying open there: the timestamps are all there is
            actual += (info.st_mtime_ns, identity._change_time(self._stream.fileno(), info))
            expected += (self.identity.mtime_ns, self.identity.change_time_ns)
        if actual != expected:
            raise ContentError("CHANGED")

    def read(self, offset: int, n: int, cancel: CancellationToken) -> bytes:
        if cancel.cancelled():
            raise ContentError("CANCELLED")
        if offset < 0 or n < 0 or offset > self.identity.size or n > self.resident_limit:
            raise ContentError("RESIDENT_LIMIT")
        amount = min(n, self.identity.size - offset)
        self._check()
        if self._last is not None and self._last[:2] == (offset, amount):
            if amount:
                self._reads.append(ByteRange(offset, offset + amount))
            return self._last[2]
        out = bytearray()
        while len(out) < amount:
            if cancel.cancelled():
                raise ContentError("CANCELLED")
            step = min(CHUNK, amount - len(out))
            if self._stream is None:
                assert self._data is not None
                block = self._data[offset + len(out):offset + len(out) + step]
            else:
                self._stream.seek(offset + len(out))
                block = self._stream.read(step)
            if not block:
                raise ContentError("CHANGED")
            out.extend(block)
        self._check()
        if amount:
            self._reads.append(ByteRange(offset, offset + amount))
        self._last = (offset, amount, bytes(out))
        return self._last[2]

    def begin_stage(self) -> None:
        self._reads.clear()

    def named_streams(self) -> tuple[tuple[str, int], ...]:
        return () if self._stream is None else identity.named_streams(self._stream.fileno())

    def os_handle(self) -> int | None:
        if self._stream is None or os.name != "nt":
            return None
        return msvcrt.get_osfhandle(self._stream.fileno())

    @property
    def ranges(self) -> tuple[ByteRange, ...]:
        return normalize_ranges(tuple(self._reads), self.identity.size)

    def close(self) -> None:
        self._last = None
        if self._stream is not None:
            self._stream.close()
            self._stream = None
