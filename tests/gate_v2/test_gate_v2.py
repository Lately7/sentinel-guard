"""Pure milestone 1 checks.

Later milestones must cover invariant 2's held-handle identity binding;
7's actual adapter emissions; 8's file/archive/rule/event/source budgets;
9 cancellation of work and action rollback; 10 the pre-action filesystem
claim; 11 the stop barrier; 12 cache key/reuse; 13 persisted exception scope;
and 15 smart-scan and runtime scope reporting.
"""

from __future__ import annotations

import os
from dataclasses import fields, replace
from enum import StrEnum
from pathlib import Path

import pytest

from sentinel.gate_v2.contract import (
    ActionCode, ActionDecision, ByteRange,
    Category, ContractError, Coverage, EngineResult, Evidence, FileIdentity,
    FinalDecision, ScanError, ScanEvent, ScanRequest, StageStatus, Strength,
    VerdictCode,
)
from sentinel.gate_v2.coverage import CoverageLedger, contains_range, normalize_ranges
from sentinel.gate_v2.policy import RequiredStages, classify_clamav_name, decide, should_auto_quarantine


def test_sentinel_home_is_temporary_outside_repository() -> None:
    home = Path(os.environ["SENTINEL_HOME"]).resolve()
    repository = Path(__file__).resolve().parents[2]
    assert not home.is_relative_to(repository)


def identity() -> FileIdentity:
    return FileIdentity("C:/sample", 1, "a" * 32, 10, "b" * 64, 1, 2)


def coverage(*, mode: str = "full") -> Coverage:
    return Coverage(10, (ByteRange(0, 10),) if mode == "full" else (ByteRange(0, 5),), mode, 0, 0, 0, 0, (), (), (), "verified")


def request(*, path: bool = False) -> ScanRequest:
    return ScanRequest(2, "scan", "file", "C:/sample" if path else None, None if path else b"sample", "test", "memory", "evidence-v1", "legacy-v0", 100, 7, True)


def hit(kind: str, *, engine: str = "core", verified: bool = True) -> Evidence:
    names = {"weak": "Heuristics.Maybe", "pua": "PUA.Win.Exploit.A", "conclusive": "Win.Virus.A", "coverage": "Heuristics.Limits.Exceeded.Size"}
    category, strength = classify_clamav_name(names[kind]) if engine == "clamav" else (Category.MALWARE, Strength.CONCLUSIVE if kind == "conclusive" else Strength.SUPPORTING)
    return Evidence(f"{engine}:{kind}", engine, kind, names[kind] if engine == "clamav" else None, category, strength, "outer", None, (ByteRange(0, 1),), "source", "a" * 64, None, verified, kind, kind == "conclusive" and engine == "core")


def result(
    status: StageStatus = StageStatus.COMPLETED, kind: str = "none", *,
    engine: str = "clamav", cov: Coverage | None = None,
    identity_value: FileIdentity | None = None,
) -> EngineResult:
    evidence = () if kind == "none" else (hit(kind, engine=engine),)
    verdict = VerdictCode.MALICIOUS if kind == "conclusive" else VerdictCode.SUSPICIOUS if kind in ("weak", "pua") else VerdictCode.UNKNOWN
    chosen_coverage = cov or coverage(mode="fixed_partial" if status is StageStatus.PARTIAL else "full")
    return EngineResult(2, engine, "file", identity_value or identity(), status, verdict, chosen_coverage, evidence, "1", "1", "digest", "READY", 0, 2, None)


def decision(results: tuple[EngineResult, ...], *, required: bool = True, disabled: bool = False) -> FinalDecision:
    ids = frozenset(item.engine_id for item in results)
    stages = RequiredStages(ids if required or disabled else frozenset(), ids if disabled else frozenset())
    return decide(results, request(), "generation", stages=stages)


def action(value: FinalDecision, policy: str = "evidence-v1", **options: object) -> ActionDecision:
    kwargs = dict(policy_version=policy, auto_quarantine=True, protection_generation=7, current_protection_generation=7, identity_reverified=True)
    kwargs.update(options)
    return should_auto_quarantine(value, **kwargs)


@pytest.mark.parametrize("status", list(StageStatus))
@pytest.mark.parametrize("kind", ["none", "weak", "pua", "conclusive", "coverage"])
@pytest.mark.parametrize("required", [True, False])
def test_verdict_cartesian_matrix(status: StageStatus, kind: str, required: bool) -> None:
    item = result(status, kind)
    value = decision((item,), required=required)
    if not required:
        if status in (StageStatus.COMPLETED, StageStatus.PARTIAL) and kind == "conclusive":
            expected = (VerdictCode.MALICIOUS, False, "CLAMAV_CONCLUSIVE")
        elif status in (StageStatus.COMPLETED, StageStatus.PARTIAL) and kind == "pua":
            expected = (VerdictCode.SUSPICIOUS, False, "PUA_DETECTION")
        elif status in (StageStatus.COMPLETED, StageStatus.PARTIAL) and kind == "weak":
            expected = (VerdictCode.SUSPICIOUS, False, "WEAK_DETECTION")
        elif kind in ("weak", "pua", "conclusive"):
            expected = (VerdictCode.UNKNOWN, False, "UNACCEPTED_DETECTION")
        else:
            expected = (VerdictCode.CLEAN, True, "COMPLETE_NO_DETECTION")
    elif status in (StageStatus.COMPLETED, StageStatus.PARTIAL):
        if kind == "conclusive":
            expected = (VerdictCode.MALICIOUS, False, "CLAMAV_CONCLUSIVE")
        elif kind == "pua":
            expected = (VerdictCode.SUSPICIOUS, False, "PUA_DETECTION")
        elif kind == "weak":
            expected = (VerdictCode.SUSPICIOUS, False, "WEAK_DETECTION")
        elif kind == "coverage":
            expected = (VerdictCode.UNKNOWN, False, "INCOMPLETE_COVERAGE")
        elif status is StageStatus.PARTIAL:
            expected = (VerdictCode.CLEAN, False, "FIXED_PARTIAL")
        else:
            expected = (VerdictCode.CLEAN, True, "COMPLETE_NO_DETECTION")
    elif status is StageStatus.TIMEOUT:
        expected = (VerdictCode.UNKNOWN, False, "ENGINE_TIMEOUT")
    elif status is StageStatus.CHANGED:
        expected = (VerdictCode.UNKNOWN, False, "CHANGED")
    elif status is StageStatus.UNVERIFIED:
        expected = (VerdictCode.UNKNOWN, False, "UNVERIFIED_ENGINE")
    elif status is StageStatus.CANCELLED:
        expected = (VerdictCode.UNKNOWN, False, "CANCELLED")
    else:
        expected = (VerdictCode.UNKNOWN, False, "ENGINE_INCOMPLETE")
    assert (value.verdict, value.trusted_clean, value.reason_codes[0]) == expected


@pytest.mark.parametrize("case", ["unverified", "bad_status", "unbound", "identity_mismatch", "disabled"])
def test_unaccepted_detection_prevents_optional_trusted_clean(case: str) -> None:
    item = result(kind="conclusive", engine="core")
    companion: tuple[EngineResult, ...] = ()
    disabled = frozenset()
    if case == "unverified":
        item = replace(item, evidence=(replace(item.evidence[0], strength=Strength.SUPPORTING, verified=False),))
    elif case == "bad_status":
        item = replace(item, status=StageStatus.UNVERIFIED)
    elif case == "unbound":
        item = replace(item, coverage=coverage(mode="fixed_partial"), evidence=(replace(item.evidence[0], ranges=(ByteRange(8, 9),)),))
    elif case == "identity_mismatch":
        companion = (result(engine="clamav", identity_value=replace(identity(), sha256="c" * 64)),)
    else:
        disabled = frozenset({"core"})
    stages = RequiredStages(disabled, disabled)
    value = decide((item, *companion), request(), "generation", stages=stages)
    assert (value.verdict, value.trusted_clean, value.cacheable) == (VerdictCode.UNKNOWN, False, False)
    assert value.accepted_evidence_ids == ()
    assert value.reason_codes[-1] == "UNACCEPTED_DETECTION"
    if case == "identity_mismatch":
        assert value.reason_codes == ("CHANGED", "UNACCEPTED_DETECTION")


def test_unverified_clamav_lead_notifies_without_trusted_clean() -> None:
    item = result(StageStatus.UNVERIFIED, "conclusive")
    value = decision((item,), required=False)
    assert (value.verdict, value.trusted_clean, value.cacheable) == (VerdictCode.UNKNOWN, False, False)
    assert value.reason_codes == ("UNACCEPTED_DETECTION",)
    assert (action(value).action, action(value).reason_code) == (ActionCode.NOTIFY, "UNVERIFIED_CLAMD")
    required_value = decision((item,), required=True)
    assert required_value.reason_codes == ("UNVERIFIED_ENGINE", "UNACCEPTED_DETECTION")


def test_accepted_detection_keeps_precedence_over_unaccepted_lead() -> None:
    dropped = result(StageStatus.UNVERIFIED, "conclusive")
    for kind, expected in (("conclusive", VerdictCode.MALICIOUS), ("weak", VerdictCode.SUSPICIOUS)):
        accepted = result(kind=kind, engine="core")
        value = decision((accepted, dropped), required=False)
        assert value.verdict is expected
        assert value.reason_codes[-1] == "UNACCEPTED_DETECTION"
        assert value.accepted_evidence_ids == (f"core:{kind}",)
        assert not value.cacheable


@pytest.mark.parametrize("category,reason", [(Category.PUA, "PUA_DETECTION"), (Category.RISKWARE, "WEAK_DETECTION")])
def test_conclusive_pua_and_riskware_are_suspicious(category: Category, reason: str) -> None:
    item = result(kind="conclusive", engine="core")
    item = replace(item, evidence=(replace(item.evidence[0], category=category),))
    value = decision((item,))
    assert (value.verdict, value.reason_codes, value.accepted_evidence_ids) == (
        VerdictCode.SUSPICIOUS, (reason,), ("core:conclusive",)
    )


@pytest.mark.parametrize("category", [Category.STRUCTURE, Category.ORIGIN, Category.HEALTH])
def test_conclusive_context_does_not_change_verdict(category: Category) -> None:
    item = result(kind="conclusive", engine="core")
    item = replace(item, evidence=(replace(item.evidence[0], category=category),))
    value = decision((item,))
    assert (value.verdict, value.trusted_clean) == (VerdictCode.CLEAN, True)


def test_invariant_1_no_false_clean_on_missing_or_failed_required_stage() -> None:
    value = decide((), request(), "generation", stages=RequiredStages(frozenset({"core"})))
    assert (value.verdict, value.trusted_clean, value.cacheable) == (VerdictCode.UNKNOWN, False, False)


def test_invariant_3_unverified_evidence_cannot_authorize_action() -> None:
    unverified = replace(hit("weak", engine="clamav"), verified=False)
    item = replace(result(StageStatus.UNVERIFIED), evidence=(unverified,))
    value = decision((item,))
    assert value.accepted_evidence_ids == ()
    assert action(value).reason_code == "UNVERIFIED_CLAMD"


def test_invariant_4_independent_axes_and_conflicting_engines() -> None:
    value = decide((result(StageStatus.COMPLETED, "conclusive", engine="core"), result(StageStatus.TIMEOUT)), request(), "generation", stages=RequiredStages(frozenset({"core", "clamav"})))
    assert value.verdict is VerdictCode.MALICIOUS
    assert not value.trusted_clean
    assert value.engine_results[1].status is StageStatus.TIMEOUT
    assert action(value).action is ActionCode.QUARANTINE


def test_invariant_5_one_conclusive_eicar_test_file_still_malicious() -> None:
    value = decision((result(kind="conclusive", engine="core"),))
    assert value.verdict is VerdictCode.MALICIOUS
    assert value.engine_results[0].evidence[0].is_test_file
    assert action(value).action is ActionCode.QUARANTINE


def test_invariant_6_weak_prefix_precedence_and_reviewed_name() -> None:
    assert classify_clamav_name("PUA.Win.Exploit.X")[1] is Strength.SUPPORTING
    assert classify_clamav_name("Win.Trojan.Suspect-34")[1] is Strength.SUPPORTING
    for name in ("Generic.X", "Gen.X", "Agent.X", "Win.Exploit.X"):
        assert classify_clamav_name(name)[1] is Strength.CONCLUSIVE
    assert decision((result(kind="weak"),)).verdict is VerdictCode.SUSPICIOUS


def test_invariant_7_coverage_children_and_stage_debt() -> None:
    ledger = CoverageLedger(10, (ByteRange(0, 10),), certainty="verified")
    ledger.child("inspected")
    ledger.child("opaque", "ENCRYPTED_MEMBER")
    ledger.child("omitted", "UNSUPPORTED_METHOD")
    value = ledger.finish()
    assert value.mode == "runtime_partial"
    assert value.object_reasons == ("ENCRYPTED_MEMBER", "UNSUPPORTED_METHOD")
    assert decision((result(cov=value),)).reason_codes == ("INCOMPLETE_COVERAGE",)


def test_unlisted_parser_state_marks_enumeration_incomplete() -> None:
    ledger = CoverageLedger(10, (ByteRange(0, 10),), certainty="verified")
    ledger.parser("archive", "timeout")
    assert not ledger.enumeration_complete
    assert ledger.finish().mode == "runtime_partial"


def test_invariant_8_bounded_reasons_and_explicit_limit() -> None:
    ledger = CoverageLedger(10)
    for _ in range(100):
        ledger.child("omitted", "MEMBER_LIMIT")
    ledger.limit("MAX_MEMBERS")
    value = ledger.finish()
    assert len(value.object_reasons) == 64
    assert value.object_reasons[-1] == "REASONS_OVERFLOW"
    assert ledger.reasons_overflow == 37
    assert value.limits_hit == ("MAX_MEMBERS",)
    capped = CoverageLedger(10, max_children=1)
    capped.child("inspected")
    capped.child("inspected")
    assert capped.finish().limits_hit == ("MAX_CHILDREN",)


def test_invariant_12_cacheable_flag_never_strengthens_incomplete() -> None:
    assert not decision((result(StageStatus.TIMEOUT),)).cacheable
    fixed = coverage(mode="fixed_partial")
    value = decision((result(StageStatus.PARTIAL, cov=fixed),))
    assert value.cacheable and not value.trusted_clean and value.reason_codes == ("FIXED_PARTIAL",)
    disabled = decision((result(StageStatus.SKIPPED),), disabled=True)
    assert disabled.verdict is VerdictCode.CLEAN
    assert not disabled.trusted_clean
    assert disabled.reason_codes == ("REDUCED_POLICY",)


def test_invariant_13_restore_and_trust_keep_finding() -> None:
    value = decision((result(kind="conclusive"),))
    for options, reason in (({"restore_exception_matches": True}, "RESTORE_EXCEPTION"), ({"trust_matches": True}, "USER_TRUST")):
        stopped = action(value, **options)
        assert stopped.action is ActionCode.NONE and stopped.reason_code == reason
        assert value.verdict is VerdictCode.MALICIOUS


def test_invariant_14_portable_event_schema_privacy() -> None:
    event = ScanEvent(1, "scan", "opaque", 1, "clamav", "finished", 2, "OK")
    assert set(event.to_dict()) == {field.name for field in fields(ScanEvent)}
    assert not set(event.to_dict()) & {"path", "sha256", "url", "raw_output", "username", "command_line"}
    with pytest.raises(TypeError):
        ScanEvent(1, "scan", "opaque", 1, "clamav", "finished", 2, "OK", path="C:/private")
    for field_name, value in (("result_code", "https://example.test/secret"), ("file_id", "a" * 64), ("stage", "C:/private")):
        with pytest.raises(ContractError):
            replace(event, **{field_name: value})


def test_range_union_containment() -> None:
    ranges = normalize_ranges((ByteRange(5, 10), ByteRange(0, 3), ByteRange(3, 6)), 10)
    assert ranges == (ByteRange(0, 10),)
    assert contains_range(ranges, ByteRange(2, 8))


@pytest.mark.parametrize("enum", [StageStatus, VerdictCode, Strength, Category, ActionCode])
def test_all_enum_values_round_trip(enum: type[StrEnum]) -> None:
    for member in enum:
        assert enum(member.value) is member


def test_every_enum_value_through_wire_contract() -> None:
    for member in StageStatus:
        item = result(member)
        assert EngineResult.from_dict(item.to_dict()).status is member
    for member in VerdictCode:
        item = replace(result(), verdict=member)
        assert EngineResult.from_dict(item.to_dict()).verdict is member
    for member in Category:
        item = replace(hit("weak"), category=member)
        assert Evidence.from_dict(item.to_dict()).category is member
    for member in Strength:
        item = replace(hit("weak"), strength=member)
        assert Evidence.from_dict(item.to_dict()).strength is member
    base = action(decision((result(),)))
    for member in ActionCode:
        item = replace(base, action=member)
        assert ActionDecision.from_dict(item.to_dict()).action is member


def test_every_dataclass_round_trip() -> None:
    item = result(kind="conclusive")
    value = decision((item,))
    objects = [ByteRange(0, 2), identity(), coverage(), hit("conclusive"), ScanError("ERROR", "read", "bad", True), item, request(), value, action(value), ScanEvent(1, "scan", None, 0, "start", "started", None, "OK")]
    for original in objects:
        assert type(original).from_dict(original.to_dict()) == original


@pytest.mark.parametrize("change,code", [
    ({"size": -1}, "INVALID_SIZE"), ({"sha256": "not-a-hash"}, "INVALID_SHA256"),
])
def test_identity_validation(change: dict[str, object], code: str) -> None:
    with pytest.raises(ContractError, match=code):
        replace(identity(), **change)


def test_contract_rejects_ranges_versions_and_invalid_enums() -> None:
    with pytest.raises(ContractError, match="UNSORTED_OR_OVERLAPPING_RANGES"):
        replace(coverage(), inspected=(ByteRange(0, 5), ByteRange(4, 10)))
    with pytest.raises(ContractError, match="OUT_OF_BOUNDS_RANGE"):
        replace(coverage(), inspected=(ByteRange(0, 11),))
    with pytest.raises(ContractError, match="UNKNOWN_CONTRACT_VERSION"):
        replace(request(), contract_version=3)
    with pytest.raises(ContractError, match="UNKNOWN_POLICY_VERSION"):
        replace(request(), policy_version="future-v9")
    with pytest.raises(ContractError, match="UNKNOWN_EVENT_VERSION"):
        ScanEvent(2, "scan", None, 0, "stage", "started", 0, "OK")
    encoded = result().to_dict()
    encoded["status"] = "bogus"
    with pytest.raises(ContractError, match="INVALID_ENUM"):
        EngineResult.from_dict(encoded)


def test_contract_rejects_negative_duration_error_and_noncompleted_clean() -> None:
    with pytest.raises(ContractError, match="INVALID_DURATION_MS"):
        replace(result(), duration_ms=-1)
    with pytest.raises(ContractError, match="COMPLETED_WITH_ERROR"):
        replace(result(), error=ScanError("E", "read", "bad", True))
    with pytest.raises(ContractError, match="NONCOMPLETED_CLEAN"):
        replace(result(StageStatus.TIMEOUT), verdict=VerdictCode.CLEAN)
    with pytest.raises(ContractError, match="UNVERIFIED_CONCLUSIVE"):
        replace(hit("conclusive"), verified=False)


def test_contract_rejects_request_input_and_missing_path_identity() -> None:
    with pytest.raises(ContractError, match="INVALID_REQUEST_INPUT"):
        replace(request(), path="C:/sample")
    with pytest.raises(ContractError, match="INVALID_REQUEST_INPUT"):
        replace(request(), data=None)
    item = result(identity_value=replace(identity(), canonical_path=None))
    with pytest.raises(ContractError, match="MISSING_IDENTITY"):
        decide((item,), request(path=True), "generation", stages=RequiredStages(frozenset({"clamav"})))


def test_contract_rejects_duplicate_engines_long_text_and_reason_count() -> None:
    with pytest.raises(ContractError, match="DUPLICATE_ENGINE_ID"):
        decide((result(), result()), request(), "generation", stages=RequiredStages(frozenset({"clamav"})))
    with pytest.raises(ContractError, match="INVALID_RAW_NAME"):
        replace(hit("weak"), raw_name="x" * 513)
    with pytest.raises(ContractError, match="INVALID_MESSAGE"):
        ScanError("E", "read", "x" * 513, False)
    with pytest.raises(ContractError, match="INVALID_MEMBER_PATH"):
        replace(hit("weak"), member_path="x" * 513)
    with pytest.raises(ContractError, match="INVALID_REASON_CODES"):
        replace(decision((result(),)), reason_codes=("X",) * 65)


def test_uninspected_hit_is_not_accepted() -> None:
    item = result(StageStatus.PARTIAL, "conclusive")
    unseen = replace(item.evidence[0], ranges=(ByteRange(8, 9),))
    value = decision((replace(item, evidence=(unseen,)),))
    assert value.verdict is VerdictCode.UNKNOWN and not value.trusted_clean
    assert action(value).action is ActionCode.RETRY


def test_action_table_both_policies_rt001() -> None:
    suspect = replace(hit("weak", engine="clamav"), raw_name="Win.Trojan.Suspect-34")
    value = decision((replace(result(kind="weak"), evidence=(suspect,)),))
    assert value.verdict is VerdictCode.SUSPICIOUS
    assert action(value, "evidence-v1").action is ActionCode.NOTIFY
    legacy = action(value, "legacy-v0")
    assert (legacy.action, legacy.reason_code) == (ActionCode.QUARANTINE, "LEGACY_V0_CLAMAV_NAME")
    assert action(value, "legacy-v0", identity_reverified=False).reason_code == "CHANGED_BEFORE_ACTION"
    assert action(value, "legacy-v0", current_protection_generation=8).reason_code == "PROTECTION_STOPPED"
    assert action(value, "legacy-v0", auto_quarantine=False).reason_code == "AUTO_DISABLED"
    assert action(value, "legacy-v0", restore_exception_matches=True).reason_code == "RESTORE_EXCEPTION"


def test_action_table_unknown_pua_and_conclusive() -> None:
    assert action(decision((result(kind="pua"),))).reason_code == "PUA_USER_CHOICE"
    assert action(decision((result(StageStatus.TIMEOUT),))).action is ActionCode.RETRY
    assert action(decision((result(kind="conclusive"),))).reason_code == "AUTO_CONCLUSIVE"
    assert action(decision((result(kind="conclusive"),)), auto_quarantine=False).reason_code == "AUTO_DISABLED"
    with pytest.raises(ContractError, match="UNKNOWN_ACTION_POLICY"):
        action(decision((result(),)), "future-v9")


@pytest.mark.parametrize("generation,current,expected", [
    (None, None, (ActionCode.QUARANTINE, "AUTO_CONCLUSIVE")),
    (7, 8, (ActionCode.NONE, "PROTECTION_STOPPED")),
    (7, None, (ActionCode.NONE, "PROTECTION_STOPPED")),
])
def test_action_stop_barrier_applies_only_to_bound_generation(
    generation: int | None, current: int | None, expected: tuple[ActionCode, str],
) -> None:
    value = decision((result(kind="conclusive", engine="core"),))
    selected = action(value, protection_generation=generation, current_protection_generation=current)
    assert (selected.action, selected.reason_code) == expected


def test_final_duration_spans_first_start_to_last_end() -> None:
    first = replace(result(engine="core"), started_monotonic_ns=1_000_000_000, duration_ms=300)
    second = replace(result(engine="clamav"), started_monotonic_ns=1_500_000_000, duration_ms=50)
    value = decision((first, second))
    assert value.duration_ms == 550
    assert decide((), request(), "generation", stages=RequiredStages(frozenset())).duration_ms == 0
