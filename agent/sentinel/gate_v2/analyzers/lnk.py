"""Bounded Shell Link target and argument observations."""
from __future__ import annotations

import re
import time
from ..content import BoundReader, ContentError
from ..contract import ByteRange, CancellationToken, Category, EngineResult, FileIdentity, ScanRequest, StageStatus, Strength
from . import context_evidence, result

MAX_LNK = 64 * 1024
_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_HOST = re.compile(r"(?:^|[\\/])(?:powershell|pwsh|cmd|mshta|wscript|cscript|rundll32)(?:\.exe)?\Z", re.I)
_HOSTS = ("powershell", "pwsh", "cmd", "mshta", "wscript", "cscript", "rundll32")


def _u16(data: bytes, at: int) -> int:
    if at + 2 > len(data):
        raise ValueError("truncated")
    return int.from_bytes(data[at:at + 2], "little")


def _u32(data: bytes, at: int) -> int:
    if at + 4 > len(data):
        raise ValueError("truncated")
    return int.from_bytes(data[at:at + 4], "little")


def _cstr(data: bytes, begin: int, end: int, unicode: bool = False) -> str:
    if begin >= end:
        return ""
    end = min(end, begin + 8192)
    if unicode:
        stop = next((i for i in range(begin, end - 1, 2) if data[i:i + 2] == b"\0\0"), end)
        stop -= (stop - begin) % 2
        return data[begin:stop].decode("utf-16le", errors="replace")
    stop = data.find(b"\0", begin, end)
    return data[begin:stop if stop >= 0 else end].decode("cp1252", errors="replace")


def _string(data: bytes, at: int, unicode: bool) -> tuple[str, int, bool, bool]:
    count = _u16(data, at)
    size = count * (2 if unicode else 1)
    at += 2
    end = min(at + size, at + 8192, len(data))
    if unicode:
        end -= (end - at) % 2
    value = data[at:end].decode("utf-16le" if unicode else "cp1252", errors="replace")
    return value, at + size, size > 8192 or at + size > len(data), count > 0


def _id_host(data: bytes) -> bool:
    folded = data.lower()
    pattern = rb"(?<![a-z0-9_])(?:powershell|pwsh|cmd|mshta|wscript|cscript|rundll32)(?:\.exe)?(?![a-z0-9_.])"
    if re.search(pattern, folded):
        return True
    return any(name.encode("utf-16le") in folded for name in _HOSTS)


def parse(data: bytes) -> tuple[bool, str]:
    if len(data) < 76 or _u32(data, 0) != 76 or data[4:20] != _CLSID:
        return False, "not_lnk"
    try:
        flags = _u32(data, 20)
        at = 76
        candidates: list[str] = []
        id_host = False
        partial = False
        if flags & 1:
            size = _u16(data, at)
            at += 2
            if at + size > len(data):
                raise ValueError("IDList")
            id_host = _id_host(data[at:at + size])
            at += size
        if flags & 2:
            size = _u32(data, at)
            header = _u32(data, at + 4)
            if size < 28 or header < 28 or header > size or at + size > len(data):
                raise ValueError("LinkInfo")
            parts: list[str] = []
            for field in (16, 24) + ((28, 32) if header >= 36 else ()):
                offset = _u32(data, at + field)
                value = _cstr(data, at + offset, at + size, field >= 28) if offset and header <= offset < size else ""
                parts.append(value)
                if value:
                    candidates.append(value)
            if parts[0] and parts[1]:
                candidates.append(parts[0] + parts[1])
            if len(parts) > 3 and parts[2] and parts[3]:
                candidates.append(parts[2] + parts[3])
            at += size
        arguments = False
        for flag in (4, 8, 16, 32, 64):
            if flags & flag:
                value, at, clipped, declared = _string(data, at, bool(flags & 0x80))
                partial |= clipped
                if flag == 8 and value:
                    candidates.append(value)
                if flag == 32:
                    arguments = declared
        for _ in range(64):
            if at + 4 > len(data):
                break
            size = _u32(data, at)
            if size == 0:
                break
            if size < 8 or at + size > len(data):
                partial = True
                break
            if _u32(data, at + 4) == 0xA0000001:
                candidates.extend((_cstr(data, at + 8, at + min(size, 268)),
                                   _cstr(data, at + 268, at + size, True)))
            at += size
        found = arguments and (id_host or any(_HOST.search(v.strip().strip('"')) for v in candidates))
        return found, "partial" if partial else "complete"
    except (ValueError, UnicodeError, OverflowError):
        return False, "malformed"


class LnkAdapter:
    engine_id = "lnk"
    reopens_path = False

    def readiness(self) -> str:
        return "READY"

    def scan_bound(self, request: ScanRequest, measured: FileIdentity,
                   cancel: CancellationToken, reader: BoundReader) -> EngineResult:
        start = time.monotonic_ns()
        try:
            head = reader.read(0, min(measured.size, 76), cancel)
            if len(head) < 76 or _u32(head, 0) != 76 or head[4:20] != _CLSID:
                return result(self.engine_id, request, measured, start, StageStatus.COMPLETED, "NOT_LNK", reader.ranges)
            data = reader.read(0, min(measured.size, MAX_LNK), cancel)
            span = reader.ranges
            found, state = parse(data)
            if measured.size > MAX_LNK:
                state = "partial"
            evidence = ((context_evidence(self.engine_id, "LNK_TARGETS_SCRIPT_HOST",
                                          Category.STRUCTURE, Strength.SUPPORTING, span),) if found else ())
            if state == "malformed":
                return result(self.engine_id, request, measured, start, StageStatus.PARTIAL,
                              "LNK_MALFORMED", span, evidence, parser_state="malformed")
            if state == "partial":
                return result(self.engine_id, request, measured, start, StageStatus.PARTIAL,
                              "LNK_SIZE_LIMIT" if measured.size > MAX_LNK else "LNK_STRING_LIMIT",
                              span, evidence, parser_state="complete")
            return result(self.engine_id, request, measured, start, StageStatus.COMPLETED,
                          "READY", span, evidence)
        except ContentError as exc:
            status = StageStatus.CHANGED if exc.code == "CHANGED" else StageStatus.CANCELLED if exc.code == "CANCELLED" else StageStatus.ERROR
            return result(self.engine_id, request, measured, start, status, exc.code, reader.ranges, parser_state="error")
        except Exception:
            return result(self.engine_id, request, measured, start, StageStatus.ERROR,
                          "LNK_ERROR", reader.ranges, parser_state="error")
