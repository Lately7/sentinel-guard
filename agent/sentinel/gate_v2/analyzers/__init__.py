"""Small shared result builder for bounded context analyzers."""

from __future__ import annotations

import time
from typing import Literal

from ..contract import (CONTRACT_VERSION, ByteRange, Category, Coverage,
                        EngineResult, Evidence, FileIdentity, ScanError,
                        ScanRequest, StageStatus, Strength, VerdictCode)


def context_evidence(engine: str, code: str, category: Category,
                     strength: Strength, spans: tuple[ByteRange, ...],
                     *, scope: Literal["outer", "origin"] = "outer") -> Evidence:
    return Evidence(f"{engine}.{code.lower()}", engine, code, None, category,
                    strength, scope, None, spans, f"sentinel-{engine}", None,
                    None, True, code)


def result(engine: str, request: ScanRequest, measured: FileIdentity, start: int,
           status: StageStatus, code: str, inspected: tuple[ByteRange, ...],
           evidence: tuple[Evidence, ...] = (), *,
           certainty: Literal["verified", "declared", "unknown"] = "unknown",
           parser_state: str = "complete") -> EngineResult:
    full = inspected == ((ByteRange(0, measured.size),) if measured.size else ())
    coverage = Coverage(measured.size, inspected,
                        "full" if full and parser_state == "complete" else
                        "fixed_partial" if inspected and parser_state == "complete" else
                        "runtime_partial" if inspected else "none",
                        0, 0, 0, 0, (), ((engine, parser_state),),
                        () if parser_state == "complete" else (code,), certainty)
    # These parsers observe context; even a complete parse is no malware scan.
    verdict = (VerdictCode.SUSPICIOUS if any(item.category is Category.STRUCTURE and
               item.strength is Strength.SUPPORTING for item in evidence) else
               VerdictCode.UNKNOWN)
    error = None if status in (StageStatus.COMPLETED, StageStatus.PARTIAL) else ScanError(
        code, engine, code, status in (StageStatus.CHANGED, StageStatus.TIMEOUT,
                                       StageStatus.ERROR))
    return EngineResult(CONTRACT_VERSION, engine, request.file_id, measured,
                        status, verdict, coverage, evidence, "context-v1", None,
                        None, code, start, max(0, (time.monotonic_ns() - start) // 1_000_000),
                        error)
