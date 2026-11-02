"""Project typed Gate v2 results into the existing display-only Verdict API."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..engine.verdict import Finding, Severity, Verdict
from .contract import Evidence, FinalDecision, StageStatus, Strength

UNKNOWN = "unknown"

_SKIPPED = {
    "CHANGED": "changed while scanning",
    "IN_USE": "unreadable: in use by another program",
    "UNREADABLE": "unreadable: cannot open",
    "NOT_REGULAR": "not a regular file",
    "TOO_LARGE": "too large to scan",
    "CANCELLED": "cancelled",
}


@dataclass
class GateVerdict(Verdict):
    decision: FinalDecision | None = None
    _projected_findings: int = field(default=0, init=False, repr=False)

    @property
    def label(self) -> str:
        # The native host still appends a critical URL blocklist finding after projection.
        if any(item.severity >= Severity.CRITICAL for item in self.findings[self._projected_findings:]):
            return "malicious"
        return self.decision.verdict.value if self.decision is not None else super().label

    def to_dict(self, max_findings: int = 200) -> dict[str, Any]:
        value = super().to_dict(max_findings)
        decision = self.decision
        value["scan_result"] = None if decision is None else {
            "contract_version": decision.contract_version,
            "verdict": decision.verdict.value,
            "trusted_clean": decision.trusted_clean,
            "policy_scope": decision.policy_scope,
            "reason_codes": list(decision.reason_codes),
            "accepted_evidence_ids": list(decision.accepted_evidence_ids),
            "gate_generation": decision.gate_generation,
            "duration_ms": decision.duration_ms,
            "stages": [
                {
                    "engine_id": result.engine_id,
                    "status": result.status.value,
                    "verdict": result.verdict.value,
                    "readiness_code": result.readiness_code,
                    "coverage_mode": result.coverage.mode,
                }
                for result in decision.engine_results
            ],
        }
        return value


def _stage_text(result: Any) -> str:
    status = result.status
    code = result.readiness_code.lower()
    if status is StageStatus.UNVERIFIED:
        return "unavailable: unverified daemon"
    if status in (StageStatus.ERROR, StageStatus.CHANGED):
        return f"error: {code}"
    if status is StageStatus.TIMEOUT:
        return f"timeout: {code}"
    if status is StageStatus.CANCELLED:
        return "skipped: cancelled"
    if status is StageStatus.UNAVAILABLE:
        return f"unavailable: {code}"
    if status is StageStatus.SKIPPED:
        return "skipped: already detected" if result.readiness_code == "CONCLUSIVE_HIT" else f"skipped: {code}"
    if result.evidence:
        return "detected"
    if status is StageStatus.PARTIAL:
        return f"partial: {code}"
    return "clean"


def _stage_worst(texts: list[str]) -> str:
    # A detection must remain visible when its partner in the combined layer failed.
    rank = {"detected": 7, "error": 6, "timeout": 5, "partial": 4,
            "unavailable": 3, "skipped": 2, "clean": 1}
    return max(texts, key=lambda text: rank.get(text.split(":", 1)[0], 0))


def _finding(item: Evidence) -> Finding:
    code = item.detail_code.upper()
    engine = item.engine_id
    if engine == "core":
        if code == "EICAR":
            kind, rule, detail = "signature", "eicar.test_file", "EICAR anti-malware test file (harmless)"
        elif code == "KNOWN_BAD_HASH":
            kind, rule, detail = "signature", "hash.known_bad", "SHA-256 listed as known malware"
        elif code in ("RTLO", "DOUBLE_EXTENSION", "PADDED_NAME", "MISMATCH"):
            kind, rule, detail = "filetype", f"filetype.{code.lower()}", f"Deceptive file name: {code.lower()}"
        elif code.startswith("PE_"):
            kind, rule, detail = "pe", f"pe.{code[3:].lower()}", f"PE structure: {code[3:].lower()}"
        elif code == "SCRIPT_INDICATOR":
            kind, rule, detail = "script", "script.indicator", "Script capability indicator"
        else:
            kind, rule, detail = "sentinel", f"sentinel.{code.lower()}", f"Core signal: {code.lower()}"
    elif engine == "json_rules":
        kind, rule = "rules", item.signature_id or item.detail_code
        detail = f"Rule match: {rule}"
    elif engine == "yara_x":
        kind, rule = "yara", f"yara.{item.signature_id or item.detail_code}"
        detail = f"YARA rule match: {item.raw_name or item.signature_id or item.detail_code}"
    elif engine == "clamav":
        kind = "clamav"
        rule = (f"clamav.{item.raw_name.split('.', 1)[0].lower()}"
                if item.raw_name and item.strength is not Strength.CONCLUSIVE else "clamav.detection")
        detail = f"ClamAV: {item.raw_name or 'detection'}"
    elif engine == "defender":
        kind, rule, detail = "defender", "defender.detection", f"Microsoft Defender: {item.raw_name or 'detection'}"
    else:
        kind, rule, detail = engine, f"{engine}.{code.lower()}", f"{engine}: {code.lower()}"
    if item.member_path:
        detail = f"{item.member_path}: {detail}"
    severity, score = {
        Strength.CONCLUSIVE: (Severity.CRITICAL, 100),
        Strength.STRONG: (Severity.HIGH, 50),
        Strength.SUPPORTING: (Severity.MEDIUM, 30),
        Strength.CONTEXT: (Severity.INFO, 0),
        Strength.COVERAGE: (Severity.INFO, 0),
    }[item.strength]
    if rule == "filetype.rtlo":
        severity = Severity.HIGH
    return Finding(kind, rule, severity, detail, score)


def _skipped(decision: FinalDecision) -> str | None:
    if not decision.reason_codes:
        return None
    top = decision.reason_codes[0]
    if top in _SKIPPED:
        return _SKIPPED[top]
    if top in ("FIXED_PARTIAL", "REDUCED_POLICY"):
        return f"partial: {top.lower()}"
    if decision.verdict.value in ("clean", "malicious", "suspicious"):
        return None
    return f"incomplete: {top.lower()}"


def project(
    decision: FinalDecision, *, name: str, path: str | None,
    stage_defaults: dict[str, str],
) -> GateVerdict:
    layers: dict[str, list[str]] = {"sentinel": [], "rules+yara": [], "defender": []}
    if "clamav" in stage_defaults:
        layers["clamav"] = []
    findings: list[Finding] = []
    for result in decision.engine_results:
        layer = {"core": "sentinel", "json_rules": "rules+yara", "yara_x": "rules+yara"}.get(result.engine_id)
        if layer is None and result.engine_id in ("clamav", "defender"):
            layer = result.engine_id
        if layer is not None:
            layers.setdefault(layer, []).append(_stage_text(result))
        findings.extend(_finding(item) for item in result.evidence)
    engines = {
        layer: _stage_worst(texts) if texts else stage_defaults.get(layer, "unavailable: not run")
        for layer, texts in layers.items()
        if layer != "clamav" or texts or layer in stage_defaults
    }
    identity = decision.identity
    verdict = GateVerdict(
        name=name, sha256=identity.sha256 if identity else "",
        size=identity.size if identity else 0, findings=findings,
        path=path, skipped=_skipped(decision), engines=engines, decision=decision,
    )
    verdict._projected_findings = len(findings)
    return verdict
