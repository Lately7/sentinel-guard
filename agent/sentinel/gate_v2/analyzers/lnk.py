"""Bounded Shell Link target and argument observations (MS-SHLLINK)."""

from __future__ import annotations

import re
import time

from ..content import BoundReader, ContentError
from ..contract import (ByteRange, CancellationToken, Category, EngineResult,
                        FileIdentity, ScanRequest, StageStatus, Strength)
from . import context_evidence, result

MAX_LNK = 64 * 1024
_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_HOST = re.compile(r"(?:^|[\\/])(?:powershell|pwsh|cmd|mshta|wscript|cscript|rundll32)(?:\.exe)?\Z", re.I)


def _u16(data: bytes, at: int) -> int:
    if at + 2 > len(data):
        raise ValueError("truncated length")
    return int.from_bytes(data[at:at + 2], "little")


def _u32(data: bytes, at: int) -> int:
    if at + 4 > len(data):
        raise ValueError("truncated length")
    return int.from_bytes(data[at:at + 4], "little")


def _string(data: bytes, at: int, unicode: bool) -> tuple[str, int]:
    count = _u16(data, at)
    size = count * (2 if unicode else 1)
    at += 2
    if size > 8192 or at + size > len(data):
        raise ValueError("string limit")
    return data[at:at + size].decode("utf-16le" if unicode else "cp1252", errors="replace"), at + size


def parse(data: bytes) -> tuple[str | None, str | None, str]:
    if len(data) < 76 or _u32(data, 0) != 76 or data[4:20] != _CLSID:
        return None, None, "malformed"
    try:
        flags = _u32(data, 20)
        at = 76
        if flags & 1:  # LinkTargetIDList
            at += 2 + _u16(data, at)
            if at > len(data):
                raise ValueError("ID list")
        target = None
        if flags & 2:  # LinkInfo; offsets are relative to its start.
            size = _u32(data, at)
            header = _u32(data, at + 4)
            if size < 28 or size > MAX_LNK or header < 28 or header > size or at + size > len(data):
                raise ValueError("LinkInfo")
            for field in (16, 24):  # LocalBasePath and CommonPathSuffix
                offset = _u32(data, at + field)
                if offset:
                    if offset < header or offset >= size:
                        raise ValueError("LinkInfo offset")
                    end = data.find(b"\0", at + offset, at + size)
                    if end < 0:
                        raise ValueError("LinkInfo string")
                    value = data[at + offset:end].decode("cp1252", errors="replace")
                    if field == 16 and value:
                        target = value
            if header >= 36:
                offset = _u32(data, at + 28)  # LocalBasePathUnicode
                if offset:
                    if offset < header or offset >= size:
                        raise ValueError("Unicode LinkInfo offset")
                    begin = at + offset
                    end = next((i for i in range(begin, min(at + size - 1, begin + 8192), 2)
                                if data[i:i + 2] == b"\0\0"), -1)
                    if end < 0:
                        raise ValueError("Unicode LinkInfo string")
                    target = data[begin:end].decode("utf-16le")
            at += size
        strings: dict[int, str] = {}
        for flag in (4, 8, 16, 32, 64):
            if flags & flag:
                strings[flag], at = _string(data, at, bool(flags & 0x80))
        return strings.get(8) or target, strings.get(32), "complete"
    except (ValueError, UnicodeError, OverflowError):
        return None, None, "malformed"


class LnkAdapter:
    engine_id = "lnk"
    reopens_path = False

    def readiness(self) -> str:
        return "READY"

    def scan_bound(self, request: ScanRequest, measured: FileIdentity,
                   cancel: CancellationToken, reader: BoundReader) -> EngineResult:
        start = time.monotonic_ns()
        try:
            if measured.size > MAX_LNK:
                return result(self.engine_id, request, measured, start, StageStatus.PARTIAL,
                              "LNK_SIZE_LIMIT", (), parser_state="partial")
            data = reader.read(0, measured.size, cancel)
            span = (ByteRange(0, measured.size),) if measured.size else ()
            target, arguments, state = parse(data)
            if state != "complete":
                return result(self.engine_id, request, measured, start, StageStatus.PARTIAL,
                              "LNK_MALFORMED", span, parser_state="malformed")
            evidence = ()
            if target and arguments and _HOST.search(target.strip().strip('"')):
                evidence = (context_evidence(self.engine_id, "LNK_TARGETS_SCRIPT_HOST",
                                             Category.STRUCTURE, Strength.SUPPORTING, span),)
            return result(self.engine_id, request, measured, start, StageStatus.COMPLETED,
                          "READY", span, evidence)
        except ContentError as exc:
            status = StageStatus.CHANGED if exc.code == "CHANGED" else StageStatus.CANCELLED if exc.code == "CANCELLED" else StageStatus.ERROR
            return result(self.engine_id, request, measured, start, status, exc.code,
                          reader.ranges, parser_state="error")
        except Exception:
            return result(self.engine_id, request, measured, start, StageStatus.ERROR,
                          "LNK_ERROR", reader.ranges, parser_state="error")
