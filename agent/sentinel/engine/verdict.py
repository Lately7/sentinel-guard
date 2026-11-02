"""Shared result types for every detection engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    engine: str  # "signature", "pe", "script", "archive", "office", "url", ...
    rule: str  # stable id, e.g. "pe.injection_imports"
    severity: Severity
    detail: str  # short human-readable explanation (English)
    score: int  # contribution to the 0..100 risk score

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


CLEAN = "clean"
SUSPICIOUS = "suspicious"
MALICIOUS = "malicious"

SUSPICIOUS_AT = 30
MALICIOUS_AT = 70


@dataclass
class Verdict:
    name: str
    sha256: str
    size: int
    findings: list[Finding] = field(default_factory=list)
    path: str | None = None
    skipped: str | None = None  # reason the content was not fully inspected

    @property
    def score(self) -> int:
        # Each rule counts once (its strongest hit): five macro documents in one
        # archive are one signal, not five, and must not add up to "malicious".
        best: dict[str, int] = {}
        for f in self.findings:
            best[f.rule] = max(best.get(f.rule, 0), max(0, f.score))
        return min(100, sum(best.values()))

    @property
    def label(self) -> str:
        # A CRITICAL finding (signature hit, blocklisted hash) is conclusive on
        # its own; everything else has to accumulate.
        if any(f.severity >= Severity.CRITICAL for f in self.findings):
            return MALICIOUS
        s = self.score
        if s >= MALICIOUS_AT:
            return MALICIOUS
        if s >= SUSPICIOUS_AT:
            return SUSPICIOUS
        return CLEAN

    def to_dict(self, max_findings: int = 200) -> dict[str, Any]:
        ranked = sorted(self.findings, key=lambda f: (f.severity, f.score), reverse=True)
        return {
            "name": self.name,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "score": self.score,
            "label": self.label,
            "skipped": self.skipped,
            "findings": [f.to_dict() for f in ranked[:max_findings]],
            "findings_total": len(self.findings),
        }
