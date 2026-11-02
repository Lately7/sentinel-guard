"""One bounded ZIP walk, with a separate coverage ledger for each engine."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Callable

from .. import config
from .content import ContentError
from .contract import CancellationToken
from .coverage import CoverageLedger

MemberCheck = Callable[[str, bytes], None]
ZIP_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06")
_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
            zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA)
_PARSE_ERRORS = (OSError, ValueError, RuntimeError, EOFError,
                 zipfile.BadZipFile, NotImplementedError)


def walk(data: bytes, ledger: CoverageLedger, cancel: CancellationToken,
         inspect: MemberCheck) -> None:
    """Call inspect before recording a member as inspected by this engine."""
    count = 0
    declared = 0

    def visit(payload: bytes, depth: int, parent: str) -> None:
        nonlocal count, declared
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                for info in archive.infolist():
                    if cancel.cancelled():
                        raise ContentError("CANCELLED")
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
                        if body.startswith(ZIP_PREFIXES):
                            visit(body, depth + 1, member_path)
                ledger.parser("zip", "complete")
        except _PARSE_ERRORS:
            ledger.parser("zip", "partial")

    visit(data, 0, "")
