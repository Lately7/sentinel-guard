"""Deterministic evidence, verdict, cache and action decisions."""

from __future__ import annotations

from dataclasses import dataclass

from .contract import (
    CONTRACT_VERSION, EVIDENCE_POLICY_VERSION, LEGACY_POLICY_VERSION,
    ActionCode, ActionDecision, Category, ContractError, EngineResult,
    Evidence, FinalDecision, ScanRequest, StageStatus, Strength, VerdictCode,
)
from .coverage import contains_range

_COVERAGE_PREFIXES = ("Heuristics.Limits.Exceeded.", "Heuristics.Encrypted.")
_WEAK_PREFIXES = ("PUA.", "Heuristics.", "BC.Heuristics.", "Weak.")
_WEAK_NAMES = frozenset({"Win.Trojan.Suspect-34"})
_BAD_STATUSES = {
    StageStatus.SKIPPED, StageStatus.UNAVAILABLE, StageStatus.ERROR,
    StageStatus.TIMEOUT, StageStatus.CANCELLED, StageStatus.UNVERIFIED,
    StageStatus.CHANGED,
}


@dataclass(frozen=True)
class RequiredStages:
    """Explicit applicability and disabled-by-policy declarations."""

    required: frozenset[str]
    disabled_by_policy: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.disabled_by_policy <= self.required:
            raise ContractError("INVALID_REQUIRED_STAGES")
        if any(not value or len(value) > 128 for value in self.required):
            raise ContractError("INVALID_REQUIRED_STAGES")


def classify_clamav_name(name: str) -> tuple[Category, Strength]:
    if not name or len(name) > 512:
        raise ContractError("INVALID_RAW_NAME")
    if name.startswith(_COVERAGE_PREFIXES):
        return Category.HEALTH, Strength.COVERAGE
    if name.startswith(_WEAK_PREFIXES) or name in _WEAK_NAMES:
        return (Category.PUA if name.startswith("PUA.") else Category.MALWARE), Strength.SUPPORTING
    return Category.MALWARE, Strength.CONCLUSIVE


def _effective_evidence(result: EngineResult, evidence: Evidence) -> tuple[Category, Strength]:
    if result.engine_id == "clamav" and evidence.raw_name:
        category, strength = classify_clamav_name(evidence.raw_name)
        # The name policy cannot make unverified source evidence conclusive.
        if not evidence.verified:
            return category, Strength.SUPPORTING if strength is Strength.CONCLUSIVE else strength
        return category, strength
    return evidence.category, evidence.strength


def _reason_for_hit(result: EngineResult) -> str:
    if result.engine_id == "clamav":
        return "CLAMAV_CONCLUSIVE"
    if result.engine_id == "defender":
        return "DEFENDER_THREAT"
    return "CONCLUSIVE_LOCAL"


def decide(
    results: tuple[EngineResult, ...], request: ScanRequest, gate_generation: str,
    *, stages: RequiredStages,
) -> FinalDecision:
    if not gate_generation or len(gate_generation) > 128:
        raise ContractError("INVALID_GATE_GENERATION")
    ids = [result.engine_id for result in results]
    if len(ids) != len(set(ids)):
        raise ContractError("DUPLICATE_ENGINE_ID")
    if any(result.file_id != request.file_id for result in results):
        raise ContractError("MISMATCHED_FILE_ID")
    if any(result.contract_version != CONTRACT_VERSION for result in results):
        raise ContractError("UNKNOWN_CONTRACT_VERSION")
    if request.path is not None and any(
        item.status is StageStatus.COMPLETED and
        (item.identity.canonical_path is None or item.identity.volume_serial is None or item.identity.file_id_hex is None)
        for item in results
    ):
        raise ContractError("MISSING_IDENTITY")

    identity = results[0].identity if results else None
    identity_mismatch = any(result.identity != identity for result in results)
    accepted: list[str] = []
    conclusive: list[str] = []
    weak: list[tuple[Category, Strength]] = []
    coverage_name = False
    unbound_evidence = False
    unaccepted_detection = False
    for result in results:
        for evidence in result.evidence:
            category, strength = _effective_evidence(result, evidence)
            if strength is Strength.COVERAGE:
                if result.engine_id in stages.required and result.engine_id not in stages.disabled_by_policy:
                    coverage_name = True
                continue
            # Structure, origin, and health evidence provide context, even at conclusive strength.
            if category not in (Category.MALWARE, Category.PUA, Category.RISKWARE) or strength not in (
                Strength.CONCLUSIVE, Strength.STRONG, Strength.SUPPORTING,
            ):
                continue
            if (result.engine_id in stages.disabled_by_policy or not evidence.verified or
                result.status in _BAD_STATUSES or identity_mismatch):
                unaccepted_detection = True
                continue
            if not evidence.ranges or any(not contains_range(result.coverage.inspected, span) for span in evidence.ranges):
                if result.engine_id in stages.required:
                    unbound_evidence = True
                unaccepted_detection = True
                continue
            if strength is Strength.CONCLUSIVE and category is Category.MALWARE:
                accepted.append(evidence.evidence_id)
                conclusive.append(_reason_for_hit(result))
            else:
                accepted.append(evidence.evidence_id)
                weak.append((category, strength))

    missing = stages.required - stages.disabled_by_policy - set(ids)
    incomplete: list[str] = []
    if missing:
        incomplete.append("MISSING_STAGE")
    if identity_mismatch:
        incomplete.append("CHANGED")
    if unbound_evidence:
        incomplete.append("UNBOUND_EVIDENCE")
    reduced = bool(stages.disabled_by_policy)
    for result in results:
        if result.engine_id not in stages.required or result.engine_id in stages.disabled_by_policy:
            continue
        status = result.status
        if status is StageStatus.TIMEOUT:
            incomplete.append("ENGINE_TIMEOUT")
        elif status is StageStatus.CHANGED:
            incomplete.append("CHANGED")
        elif status is StageStatus.UNVERIFIED:
            incomplete.append("UNVERIFIED_ENGINE")
        elif status is StageStatus.CANCELLED:
            incomplete.append("CANCELLED")
        elif status in (StageStatus.ERROR, StageStatus.UNAVAILABLE, StageStatus.SKIPPED):
            incomplete.append("ENGINE_INCOMPLETE")
        elif status is StageStatus.PARTIAL:
            if result.coverage.mode == "fixed_partial":
                reduced = True
            else:
                incomplete.append("INCOMPLETE_COVERAGE")
        if result.coverage.mode in ("runtime_partial", "none") or result.coverage.objects_opaque or result.coverage.objects_omitted or result.coverage.limits_hit:
            incomplete.append("INCOMPLETE_COVERAGE")
        elif result.coverage.mode == "fixed_partial":
            reduced = True
        if result.coverage.certainty != "verified" and status is StageStatus.COMPLETED:
            # Milestone 4 must resolve verified-daemon ClamAV OK with declared outer-byte coverage.
            incomplete.append("UNCERTAIN_COVERAGE")
    if coverage_name:
        incomplete.append("INCOMPLETE_COVERAGE")
    if unaccepted_detection:
        incomplete.append("UNACCEPTED_DETECTION")

    if conclusive:
        verdict = VerdictCode.MALICIOUS
        reasons = tuple(dict.fromkeys(conclusive))
        if unaccepted_detection:
            reasons += ("UNACCEPTED_DETECTION",)
    elif weak:
        verdict = VerdictCode.SUSPICIOUS
        lead = "PUA_DETECTION" if any(category is Category.PUA for category, _ in weak) else "WEAK_DETECTION"
        reasons = (lead, "UNACCEPTED_DETECTION") if unaccepted_detection else (lead,)
    elif incomplete:
        verdict = VerdictCode.UNKNOWN
        reasons = tuple(dict.fromkeys(incomplete))
    elif reduced:
        verdict = VerdictCode.CLEAN
        reasons = ("REDUCED_POLICY",) if stages.disabled_by_policy else ("FIXED_PARTIAL",)
    else:
        verdict = VerdictCode.CLEAN
        reasons = ("COMPLETE_NO_DETECTION",)

    trusted = verdict is VerdictCode.CLEAN and not reduced and not incomplete
    deterministic = not incomplete and all(
        item.status is StageStatus.COMPLETED or
        (item.status is StageStatus.PARTIAL and item.coverage.mode == "fixed_partial") or
        item.engine_id in stages.disabled_by_policy
        for item in results
    )
    cacheable = deterministic and identity is not None and bool(gate_generation)
    return FinalDecision(
        CONTRACT_VERSION, request.scan_id, request.file_id, identity,
        verdict, trusted, "reduced" if reduced else "full", reasons,
        tuple(dict.fromkeys(accepted)), results, cacheable, gate_generation,
        ((max(item.started_monotonic_ns + item.duration_ms * 1_000_000 for item in results) -
          min(item.started_monotonic_ns for item in results)) // 1_000_000) if results else 0,
    )


def should_auto_quarantine(
    decision: FinalDecision, *, policy_version: str = LEGACY_POLICY_VERSION,
    auto_quarantine: bool, protection_generation: int | None,
    current_protection_generation: int | None,
    identity_reverified: bool, restore_exception_matches: bool = False,
    trust_matches: bool = False,
) -> ActionDecision:
    if policy_version not in (EVIDENCE_POLICY_VERSION, LEGACY_POLICY_VERSION):
        raise ContractError("UNKNOWN_ACTION_POLICY")

    legacy_ids: list[str] = []
    if policy_version == LEGACY_POLICY_VERSION:
        for result in decision.engine_results:
            if result.engine_id != "clamav" or result.status not in (StageStatus.COMPLETED, StageStatus.PARTIAL) or result.identity != decision.identity:
                continue
            for item in result.evidence:
                if (item.verified and item.raw_name and item.ranges and
                    all(contains_range(result.coverage.inspected, span) for span in item.ranges) and
                    not item.raw_name.startswith(("Heuristics.", "PUA."))):
                    legacy_ids.append(item.evidence_id)

    has_hit = decision.verdict is VerdictCode.MALICIOUS and bool(decision.accepted_evidence_ids)
    wants_action = has_hit or bool(legacy_ids)
    evidence_ids = tuple(dict.fromkeys((*decision.accepted_evidence_ids, *legacy_ids)))
    if protection_generation is not None and protection_generation != current_protection_generation:
        action, reason = ActionCode.NONE, "PROTECTION_STOPPED"
    elif wants_action and not identity_reverified:
        action, reason = ActionCode.NONE, "CHANGED_BEFORE_ACTION"
    elif restore_exception_matches:
        action, reason = ActionCode.NONE, "RESTORE_EXCEPTION"
    elif trust_matches:
        action, reason = ActionCode.NONE, "USER_TRUST"
    elif wants_action and not auto_quarantine:
        action, reason = ActionCode.NOTIFY, "AUTO_DISABLED"
    elif has_hit and auto_quarantine:
        action, reason = ActionCode.QUARANTINE, "AUTO_CONCLUSIVE"
    elif legacy_ids and auto_quarantine:
        action, reason = ActionCode.QUARANTINE, "LEGACY_V0_CLAMAV_NAME"
    elif any(item.status is StageStatus.UNVERIFIED and item.engine_id == "clamav" and item.evidence for item in decision.engine_results):
        action, reason = ActionCode.NOTIFY, "UNVERIFIED_CLAMD"
    elif decision.verdict is VerdictCode.SUSPICIOUS:
        action, reason = (ActionCode.REVIEW, "PUA_USER_CHOICE") if "PUA_DETECTION" in decision.reason_codes else (ActionCode.NOTIFY, "WEAK_ONLY")
    elif decision.verdict is VerdictCode.UNKNOWN:
        action, reason = ActionCode.RETRY, "INCOMPLETE_COVERAGE"
    else:
        action, reason = ActionCode.NONE, "NO_ACTION"
    return ActionDecision(
        CONTRACT_VERSION, policy_version, action, reason, evidence_ids,
        decision.file_id, decision.identity, protection_generation,
        action is ActionCode.QUARANTINE,
    )
