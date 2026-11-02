"""Bounded local signatures, structural signals, and ZIP inventory."""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable
from pathlib import PurePath

from ..engine import filetype
from . import archive
from .content import BoundReader, ContentError
from .contract import (CONTRACT_VERSION, CancellationToken, Category,
                       EngineResult, Evidence, FileIdentity, ScanError,
                       ScanRequest, StageStatus, Strength, VerdictCode)
from .coverage import CoverageLedger
from .evidence import select_evidence

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
        def add(code: str, category: Category, strength: Strength, *,
                test: bool = False, member_path: str | None = None) -> None:
            span = reader.ranges[:1]
            # An empty file has no byte to point at, and a hit on it still counts.
            if span or not measured.size:
                evidence.append(Evidence(f"core.{code.lower()}", self.engine_id, code, None,
                                         category, strength, "member" if member_path else "outer",
                                         member_path, span, "sentinel-core",
                                         None, None, True, code, test))

        def inspect(name: str, payload: bytes, member_path: str | None = None) -> None:
            digest = hashlib.sha256(payload).hexdigest() if member_path else measured.sha256
            if digest == EICAR_SHA256:
                add("EICAR", Category.MALWARE, Strength.CONCLUSIVE, test=True,
                    member_path=member_path)
            else:
                try:
                    if self.known_bad(digest):
                        add("KNOWN_BAD_HASH", Category.MALWARE, Strength.CONCLUSIVE,
                            member_path=member_path)
                except Exception:
                    nonlocal status
                    status = StageStatus.PARTIAL
                    ledger.parser("hash_lookup", "error")
            for finding in filetype.check_name(PurePath(name).name, payload[:4096]):
                if finding.rule in ("filetype.rtlo", "filetype.double_extension", "filetype.padded_name", "filetype.mismatch"):
                    add(finding.rule.replace("filetype.", "").upper(), Category.MALWARE,
                        Strength.SUPPORTING, member_path=member_path)
            for code in _pe_signals(payload):
                add(code, Category.STRUCTURE,
                    Strength.CONTEXT if code == "PE_CERTIFICATE_DECLARED" else Strength.SUPPORTING,
                    member_path=member_path)
            if filetype.extension(name) in filetype.SCRIPT_EXTS and any(
                marker in payload.lower() for marker in (b"invoke-expression", b"frombase64string", b"wscript.shell")):
                add("SCRIPT_INDICATOR", Category.STRUCTURE, Strength.SUPPORTING,
                    member_path=member_path)
        try:
            # Content hashing was completed through this same handle before stages.
            body = reader.read(0, min(measured.size, reader.resident_limit), cancel)
            ledger.inspected = reader.ranges
            if measured.size > len(body):
                ledger.fixed_reduction = True
            inspect(PurePath(request.path or "").name, body)
            if body.startswith(archive.ZIP_PREFIXES):
                if measured.size == len(body):
                    stopped = archive.walk(body, ledger, cancel, lambda path, payload: inspect(path, payload, path),
                                           request.deadline_monotonic_ns)
                    if stopped == "DEADLINE":
                        status = StageStatus.TIMEOUT
                        error = ScanError("DEADLINE", "archive", "DEADLINE", True)
                    elif stopped == "CANCELLED":
                        status = StageStatus.CANCELLED
                else:
                    ledger.parser("zip", "partial")
        except ContentError as exc:
            status = StageStatus.CHANGED if exc.code == "CHANGED" else StageStatus.CANCELLED if exc.code == "CANCELLED" else StageStatus.ERROR
            error = ScanError(exc.code, "read", exc.code, True)
            ledger.inspected = reader.ranges
        retained = select_evidence(evidence, ledger)
        coverage = ledger.finish()
        if coverage.mode in ("runtime_partial", "fixed_partial") and status is StageStatus.COMPLETED:
            status = StageStatus.PARTIAL
        verdict = (VerdictCode.MALICIOUS if any(e.strength is Strength.CONCLUSIVE for e in retained)
                   else VerdictCode.SUSPICIOUS if any(e.category is Category.MALWARE for e in retained)
                   else VerdictCode.CLEAN if status is StageStatus.COMPLETED else VerdictCode.UNKNOWN)
        return EngineResult(CONTRACT_VERSION, self.engine_id, request.file_id, measured,
                            status, verdict, coverage, retained, "core-v2", None,
                            None, "READY" if status is StageStatus.COMPLETED else status.value.upper(),
                            start, (time.monotonic_ns() - start) // 1_000_000, error)
