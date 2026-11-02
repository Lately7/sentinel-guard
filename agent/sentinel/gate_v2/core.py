"""Bounded local signatures, structural signals, and ZIP inventory."""

from __future__ import annotations

import io
import math
import time
import zipfile
from collections.abc import Callable
from pathlib import PurePath

from .. import config
from ..engine import filetype
from .content import BoundReader, ContentError
from .contract import (CONTRACT_VERSION, ByteRange, CancellationToken, Category,
                       Coverage, EngineResult, Evidence, FileIdentity, ScanError,
                       ScanRequest, StageStatus, Strength, VerdictCode)
from .coverage import CoverageLedger

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
HashLookup = Callable[[str], bool]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [data.count(i) for i in range(256)]
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in counts if n)


def _pe_signals(data: bytes) -> tuple[str, ...]:
    if not data.startswith(b"MZ"):
        return ()
    try:
        offset = int.from_bytes(data[0x3c:0x40], "little")
        if len(data) < 64 or offset < 64 or data[offset:offset + 4] != b"PE\0\0":
            return ("PE_MALFORMED",)
        count = int.from_bytes(data[offset + 6:offset + 8], "little")
        opt_size = int.from_bytes(data[offset + 20:offset + 22], "little")
        opt = offset + 24
        magic = int.from_bytes(data[opt:opt + 2], "little")
        if magic not in (0x10b, 0x20b) or opt + opt_size > len(data) or count > 96:
            return ("PE_MALFORMED",)
        signals: list[str] = []
        cert = opt + (96 if magic == 0x10b else 112) + 32
        if cert + 8 <= opt + opt_size and int.from_bytes(data[cert + 4:cert + 8], "little"):
            signals.append("PE_CERTIFICATE_DECLARED")
        sections = opt + opt_size
        if sections + count * 40 > len(data):
            return tuple(signals + ["PE_MALFORMED"])
        for i in range(count):
            start = sections + i * 40
            raw_size = int.from_bytes(data[start + 16:start + 20], "little")
            raw_offset = int.from_bytes(data[start + 20:start + 24], "little")
            flags = int.from_bytes(data[start + 36:start + 40], "little")
            if raw_offset + raw_size > len(data):
                signals.append("PE_MALFORMED")
                continue
            if flags & 0x20000000 and raw_size >= 4096 and _entropy(data[raw_offset:raw_offset + min(raw_size, 1 << 20)]) > 7.4:
                signals.append("PE_PACKED_SECTION")
        return tuple(dict.fromkeys(signals))
    except (IndexError, ValueError, OverflowError):
        return ("PE_MALFORMED",)


def _inventory(data: bytes, ledger: CoverageLedger, depth: int = 0) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            for index, info in enumerate(infos):
                if index >= config.MAX_ARCHIVE_MEMBERS:
                    ledger.child("omitted", "MEMBER_LIMIT")
                elif depth >= config.MAX_ARCHIVE_DEPTH:
                    ledger.child("omitted", "DEPTH_LIMIT")
                elif info.flag_bits & 1:
                    ledger.child("opaque", "ENCRYPTED")
                elif info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
                                                 zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
                    ledger.child("opaque", "UNSUPPORTED_METHOD")
                elif info.file_size > config.MAX_DEEP_SCAN_BYTES:
                    ledger.child("omitted", "MEMBER_SIZE_LIMIT")
                elif sum(i.file_size for i in infos[:index + 1]) > config.MAX_ARCHIVE_TOTAL_BYTES:
                    ledger.child("omitted", "EXPANSION_LIMIT")
                else:
                    try:
                        with archive.open(info) as member:
                            body = member.read(config.MAX_DEEP_SCAN_BYTES + 1)
                        if len(body) != info.file_size:
                            ledger.child("omitted", "MEMBER_SIZE_MISMATCH")
                        else:
                            ledger.child("inspected")
                            if body.startswith(b"PK\x03\x04"):
                                _inventory(body, ledger, depth + 1)
                    except (OSError, ValueError, RuntimeError, EOFError, zipfile.BadZipFile,
                            NotImplementedError):
                        ledger.child("opaque", "MEMBER_PARSE_ERROR")
            ledger.parser("zip", "complete")
    except (OSError, ValueError, RuntimeError, EOFError, zipfile.BadZipFile, NotImplementedError):
        ledger.parser("zip", "partial")


class CoreAdapter:
    engine_id = "core"
    reopens_path = False

    def __init__(self, known_bad: HashLookup | None = None) -> None:
        self.known_bad = known_bad or (lambda digest: False)

    def readiness(self) -> str:
        return "READY"

    def scan_bound(self, request: ScanRequest, measured: FileIdentity,
                   cancel: CancellationToken, reader: BoundReader) -> EngineResult:
        start = time.monotonic_ns()
        ledger = CoverageLedger(measured.size, certainty="verified")
        evidence: list[Evidence] = []
        status = StageStatus.COMPLETED
        error = None
        def add(code: str, category: Category, strength: Strength, *, test: bool = False) -> None:
            span = reader.ranges[:1]
            if span:
                evidence.append(Evidence(f"core.{code.lower()}", self.engine_id, code, None,
                                         category, strength, "outer", None, span, "sentinel-core",
                                         None, None, True, code, test))
        try:
            # Content hashing was completed through this same handle before stages.
            body = reader.read(0, min(measured.size, reader.resident_limit), cancel)
            ledger.inspected = reader.ranges
            if measured.size > len(body):
                ledger.fixed_reduction = True
            if measured.sha256 == EICAR_SHA256:
                add("EICAR", Category.MALWARE, Strength.CONCLUSIVE, test=True)
            else:
                try:
                    if self.known_bad(measured.sha256):
                        add("KNOWN_BAD_HASH", Category.MALWARE, Strength.CONCLUSIVE)
                except Exception:
                    status = StageStatus.PARTIAL
                    ledger.parser("hash_lookup", "error")
            name = PurePath(request.path or "").name
            for finding in filetype.check_name(name, body[:4096]):
                if finding.rule in ("filetype.rtlo", "filetype.double_extension", "filetype.padded_name", "filetype.mismatch"):
                    add(finding.rule.replace("filetype.", "").upper(), Category.MALWARE, Strength.SUPPORTING)
            for code in _pe_signals(body):
                add(code, Category.STRUCTURE, Strength.CONTEXT if code == "PE_CERTIFICATE_DECLARED" else Strength.SUPPORTING)
            if filetype.extension(name) in filetype.SCRIPT_EXTS and any(
                marker in body.lower() for marker in (b"invoke-expression", b"frombase64string", b"wscript.shell")):
                add("SCRIPT_INDICATOR", Category.STRUCTURE, Strength.SUPPORTING)
            if body.startswith((b"PK\x03\x04", b"PK\x05\x06")):
                if measured.size == len(body):
                    _inventory(body, ledger)
                else:
                    ledger.parser("zip", "partial")
        except ContentError as exc:
            status = StageStatus.CHANGED if exc.code == "CHANGED" else StageStatus.CANCELLED if exc.code == "CANCELLED" else StageStatus.ERROR
            error = ScanError(exc.code, "read", exc.code, True)
            ledger.inspected = reader.ranges
        coverage = ledger.finish()
        if coverage.mode in ("runtime_partial", "fixed_partial") and status is StageStatus.COMPLETED:
            status = StageStatus.PARTIAL
        verdict = (VerdictCode.MALICIOUS if any(e.strength is Strength.CONCLUSIVE for e in evidence)
                   else VerdictCode.SUSPICIOUS if any(e.category is Category.MALWARE for e in evidence)
                   else VerdictCode.CLEAN if status is StageStatus.COMPLETED else VerdictCode.UNKNOWN)
        return EngineResult(CONTRACT_VERSION, self.engine_id, request.file_id, measured,
                            status, verdict, coverage, tuple(evidence[:64]), "core-v2", None,
                            None, "READY" if status is StageStatus.COMPLETED else status.value.upper(),
                            start, (time.monotonic_ns() - start) // 1_000_000, error)
