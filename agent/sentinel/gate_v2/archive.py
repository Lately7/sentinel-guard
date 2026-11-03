"""One bounded ZIP walk, with a separate coverage ledger for each engine."""

from __future__ import annotations

import io
import struct
import time
import zipfile
from collections.abc import Callable

from .. import config
from ..engine import filetype
from .contract import CancellationToken
from .coverage import CoverageLedger

MAX_ZIP_ENTRIES = 200_000
MAX_ZIP_DIRECTORY_BYTES = 32 * 1024 * 1024
BOMB_RATIO = 200
BOMB_BYTES = 50 * 1024 * 1024
MemberCheck = Callable[[str, bytes], None]
Notice = Callable[[str, str], None]
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


def _directory_too_large(payload: bytes) -> bool:
    """A small archive can declare millions of entries; decide from the end
    record, before zipfile builds them all in memory."""
    tail = payload[-66_000:]
    at = tail.rfind(b"PK\x05\x06")
    if at < 0 or at + 22 > len(tail):
        return False
    entries = int.from_bytes(tail[at + 10:at + 12], "little")
    size = int.from_bytes(tail[at + 12:at + 16], "little")
    wide = tail.rfind(b"PK\x06\x06", 0, at)  # ZIP64 carries the real 64-bit counts
    if wide >= 0 and wide + 56 <= len(tail):
        entries = int.from_bytes(tail[wide + 32:wide + 40], "little")
        size = int.from_bytes(tail[wide + 40:wide + 48], "little")
    return entries > MAX_ZIP_ENTRIES or size > MAX_ZIP_DIRECTORY_BYTES


def _sort_key(info: zipfile.ZipInfo) -> bool:
    # Executables and archives first, so the member limit never hides them
    # behind thousands of harmless entries.
    suffix = filetype.extension(info.filename)
    return suffix not in filetype.EXECUTABLE_EXTS and suffix not in filetype.ARCHIVE_EXTS


def _has_orphan_local_header(payload: bytes, archive: zipfile.ZipFile,
                             members: list[zipfile.ZipInfo]) -> bool:
    """A streaming extractor can recover local entries absent from the directory."""
    spans: list[tuple[int, int]] = []
    for info in members:
        start = info.header_offset
        head = payload[start:start + 30]
        if len(head) < 30 or not head.startswith(b"PK\x03\x04"):
            continue
        names, extra = struct.unpack_from("<HH", head, 26)
        end = start + 30 + names + extra + info.compress_size
        if info.flag_bits & 8:
            tail = payload[end:end + 24]
            signature = 4 if tail.startswith(b"PK\x07\x08") else 0
            expected = (info.CRC, info.compress_size, info.file_size)
            if len(tail) >= signature + 12 and struct.unpack_from("<LLL", tail, signature) == expected:
                end += signature + 12
            elif len(tail) >= signature + 20 and struct.unpack_from("<LQQ", tail, signature) == expected:
                end += signature + 20
        spans.append((start, end))
    spans.sort()
    position = 0
    at = 0
    while (at := payload.find(b"PK\x03\x04", at, archive.start_dir)) >= 0:
        while position < len(spans) and spans[position][1] <= at:
            position += 1
        if position < len(spans) and spans[position][0] <= at:
            at += 4
            continue
        if at + 30 <= archive.start_dir:
            method = struct.unpack_from("<H", payload, at + 8)[0]
            names, extra = struct.unpack_from("<HH", payload, at + 26)
            if (method in _METHODS and 1 <= names <= 1024 and
                    at + 30 + names + extra <= archive.start_dir):
                return True
        at += 4
    return False


def walk(data: bytes, ledger: CoverageLedger, cancel: CancellationToken,
         inspect: MemberCheck, deadline_monotonic_ns: int,
         *, clock: Callable[[], int] = time.monotonic_ns, notice: Notice | None = None) -> str | None:
    """Call inspect before recording a member as inspected by this engine.
    `notice(code, member)` reports what can be said about a member without its bytes."""
    count = 0
    declared = 0
    tell = notice or (lambda code, member: None)

    def visit(payload: bytes, depth: int, parent: str) -> str | None:
        nonlocal count, declared
        if _directory_too_large(payload):
            tell("DIRECTORY_TOO_LARGE", parent)
            ledger.child("opaque", "DIRECTORY_TOO_LARGE")
            ledger.parser("zip", "partial")
            return None
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                members = sorted(archive.infolist(), key=_sort_key)
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
                        tell("NAME_ONLY", member_path)  # names cost nothing to check
                        ledger.child("omitted", "MAX_CHILDREN")
                    elif depth >= config.MAX_ARCHIVE_DEPTH:
                        ledger.child("omitted", "DEPTH_LIMIT")
                    elif info.flag_bits & 1:
                        if filetype.extension(info.filename) in filetype.EXECUTABLE_EXTS:
                            tell("ENCRYPTED_EXECUTABLE", member_path)
                        ledger.child("opaque", "ENCRYPTED")
                    elif info.compress_type not in _METHODS:
                        ledger.child("opaque", "UNSUPPORTED_METHOD")
                    elif (info.compress_size and info.file_size > BOMB_BYTES and
                          info.file_size / info.compress_size > BOMB_RATIO):
                        tell("ARCHIVE_BOMB", member_path)
                        ledger.child("omitted", "BOMB")
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
                if _has_orphan_local_header(payload, archive, members):
                    ledger.child("opaque", "ORPHAN_LOCAL_HEADER")
                    ledger.parser("zip", "partial")
                else:
                    ledger.parser("zip", "complete")
        except _PARSE_ERRORS:
            ledger.parser("zip", "partial")
        return None

    return visit(data, 0, "")
