"""One bounded ZIP walk, with a separate coverage ledger for each engine."""

from __future__ import annotations

import io
import struct
import time
import zipfile
from collections.abc import Callable

from .. import config
from .contract import CancellationToken
from .coverage import CoverageLedger

MemberCheck = Callable[[str, bytes], None]
ZIP_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06")
_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
            zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA)
_PARSE_ERRORS = (OSError, ValueError, RuntimeError, EOFError,
                 zipfile.BadZipFile, NotImplementedError)


def _headers_agree(payload: bytes, info: zipfile.ZipInfo) -> bool:
    """zipfile reads only the central directory, other extractors may trust the
    local header: when they differ, what we inspected may not be what unpacks."""
    head = payload[info.header_offset:info.header_offset + 30]
    if len(head) < 30 or not head.startswith(b"PK\x03\x04"):
        return False
    flags, method = struct.unpack_from("<HH", head, 6)
    if method != info.compress_type or (flags & 1) != (info.flag_bits & 1):
        return False
    if flags & 8:  # sizes live in the data descriptor after the member
        names, extra = struct.unpack_from("<HH", head, 26)
        tail = payload[info.header_offset + 30 + names + extra + info.compress_size:][:24]
        tail = tail[4:] if tail.startswith(b"PK\x07\x08") else tail
        expected = (info.CRC, info.compress_size, info.file_size)
        return ((len(tail) >= 12 and struct.unpack_from("<LLL", tail) == expected) or
                (len(tail) >= 20 and struct.unpack_from("<LQQ", tail) == expected))
    sizes = struct.unpack_from("<II", head, 18)
    return 0xffffffff in sizes or sizes == (info.compress_size, info.file_size)


def is_zip(payload: bytes) -> bool:
    """Extractors locate the directory from the end, so data prepended to a ZIP
    (a self-extractor, or a disguise) still unpacks and must still be walked."""
    if payload.startswith(ZIP_PREFIXES):
        return True
    if b"PK\x05\x06" not in payload[-66_000:]:
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(payload)):
            return True
    except _PARSE_ERRORS:
        return False


def walk(data: bytes, ledger: CoverageLedger, cancel: CancellationToken,
         inspect: MemberCheck, deadline_monotonic_ns: int,
         *, clock: Callable[[], int] = time.monotonic_ns) -> str | None:
    """Call inspect before recording a member as inspected by this engine."""
    count = 0
    declared = 0

    def visit(payload: bytes, depth: int, parent: str) -> str | None:
        nonlocal count, declared
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                members = archive.infolist()
                for index, info in enumerate(members):
                    reason = "CANCELLED" if cancel.cancelled() else "DEADLINE" if clock() >= deadline_monotonic_ns else None
                    if reason:
                        for _ in members[index:]:
                            ledger.child("omitted", reason)
                        ledger.limit(reason)
                        ledger.parser("zip", "partial")
                        return reason
                    count += 1
                    declared += max(0, info.file_size)
                    member_path = (parent + "/" + info.filename).lstrip("/")[:512]
                    if count > config.MAX_ARCHIVE_MEMBERS:
                        ledger.child("omitted", "MAX_CHILDREN")
                    elif depth >= config.MAX_ARCHIVE_DEPTH:
                        ledger.child("omitted", "DEPTH_LIMIT")
                    elif info.flag_bits & 1:
                        ledger.child("opaque", "ENCRYPTED")
                    elif info.compress_type not in _METHODS:
                        ledger.child("opaque", "UNSUPPORTED_METHOD")
                    elif info.file_size > config.MAX_DEEP_SCAN_BYTES:
                        ledger.child("omitted", "MEMBER_SIZE_LIMIT")
                    elif declared > config.MAX_ARCHIVE_TOTAL_BYTES:
                        ledger.child("omitted", "EXPANSION_LIMIT")
                    elif not _headers_agree(payload, info):
                        ledger.child("opaque", "HEADER_MISMATCH")
                    else:
                        try:
                            with archive.open(info) as member:
                                body = member.read(config.MAX_DEEP_SCAN_BYTES + 1)
                            if len(body) != info.file_size:
                                ledger.child("omitted", "MEMBER_SIZE_MISMATCH")
                                continue
                        except _PARSE_ERRORS:
                            ledger.child("opaque", "MEMBER_PARSE_ERROR")
                            continue
                        inspect(member_path, body)
                        ledger.child("inspected")
                        if is_zip(body):
                            reason = visit(body, depth + 1, member_path)
                            if reason:
                                for _ in members[index + 1:]:
                                    ledger.child("omitted", reason)
                                ledger.parser("zip", "partial")
                                return reason
                ledger.parser("zip", "complete")
        except _PARSE_ERRORS:
            ledger.parser("zip", "partial")
        return None

    return visit(data, 0, "")
