"""Two-stage policy and cache boundaries."""

from __future__ import annotations

import hashlib
import itertools

from sentinel.gate_v2.cache import cache_key, lookup, store
from sentinel.gate_v2.contract import (
    ByteRange, Category, Coverage, EngineResult, Evidence, FileIdentity,
    ScanRequest, StageStatus, Strength, VerdictCode,
)
from sentinel.gate_v2.policy import RequiredStages, decide


IDENTITY = FileIdentity("C:/synthetic", 1, "a" * 32, 1, hashlib.sha256(b"x").hexdigest(), 1, 1)


def request(*, file_id: str = "file") -> ScanRequest:
    return ScanRequest(2, "edge", file_id, None, b"x", "test", "memory", "evidence-v1",
                       "evidence-v1", 10_000_000_000, None, True)


def result(engine: str, status: StageStatus, mode: str, strength: Strength | None) -> EngineResult:
    ranges = () if mode == "none" else (ByteRange(0, 1),)
    coverage = Coverage(1, ranges, mode, 0, 0, 0, 0, (), (), (), "verified")
    evidence = () if strength is None else (Evidence(
        f"{engine}.{strength.value}", engine, "synthetic", None, Category.MALWARE,
        strength, "outer", None, (ByteRange(0, 1),), "test", None, None,
        True, "SYNTHETIC",
    ),)
    return EngineResult(2, engine, "file", IDENTITY, status,
                        VerdictCode.UNKNOWN if strength is None else VerdictCode.SUSPICIOUS,
                        coverage, evidence, "1", None, None, "READY", 0, 0, None)


def test_two_stage_status_coverage_strength_cartesian_invariants() -> None:
    # R11 invariants 1, 5, 6, 7: all two-stage combinations obey evidence and coverage rules.
    strengths = (None, *Strength)
    for first_status, first_mode, first_strength, second_status, second_mode, second_strength, second_required in itertools.product(
        StageStatus, ("full", "fixed_partial", "runtime_partial", "none"), strengths,
        StageStatus, ("full", "fixed_partial", "runtime_partial", "none"), strengths, (False, True),
    ):
        first = result("first", first_status, first_mode, first_strength)
        second = result("second", second_status, second_mode, second_strength)
        stages = RequiredStages(frozenset({"first", "second"} if second_required else {"first"}))
        decision = decide((first, second), request(), "generation", stages=stages)
        accepted_conclusive = any(
            item.status in (StageStatus.COMPLETED, StageStatus.PARTIAL)
            and item.coverage.mode != "none"
            and item.evidence and item.evidence[0].strength is Strength.CONCLUSIVE
            for item in (first, second)
        )
        assert (decision.verdict is VerdictCode.MALICIOUS) == accepted_conclusive
        if first_status not in (StageStatus.COMPLETED, StageStatus.PARTIAL) or first_mode in ("runtime_partial", "none"):
            assert not decision.trusted_clean
        if second_required and (second_status not in (StageStatus.COMPLETED, StageStatus.PARTIAL) or second_mode in ("runtime_partial", "none")):
            assert not decision.trusted_clean
        if decision.trusted_clean:
            assert decision.verdict is VerdictCode.CLEAN and decision.policy_scope == "full"
        if decision.verdict is VerdictCode.UNKNOWN:
            assert not decision.cacheable


class MemoryCache:
    def __init__(self) -> None:
        self.rows: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.rows.get(key)

    def put(self, key: str, payload: str, expires_at: float) -> None:
        self.rows[key] = payload


def clean_decision():
    return decide((result("first", StageStatus.COMPLETED, "full", None),),
                  request(), "generation-a", stages=RequiredStages(frozenset({"first"})))


def test_cache_same_identity_different_policy_generation_misses() -> None:
    # R11 invariant 12: policy changes cannot inherit a former trusted-clean answer.
    cache = MemoryCache()
    decision = clean_decision()
    store(cache, decision, 100.0)
    assert lookup(cache, IDENTITY, "generation-b", request(), 101.0) is None
    assert cache_key(IDENTITY, "generation-a") != cache_key(IDENTITY, "generation-b")


def test_cache_expiry_at_exact_second_misses() -> None:
    # R11 invariant 12: a decision has no authority at its expiration instant.
    cache = MemoryCache()
    decision = clean_decision()
    store(cache, decision, 100.0)
    from sentinel.gate_v2.cache import LONG_TTL
    assert lookup(cache, IDENTITY, "generation-a", request(), 100.0 + LONG_TTL) is None


def test_cache_clock_reversal_does_not_extend_trust() -> None:
    # R11 invariant 12: a wall-clock rollback must not extend a stored clean result.
    cache = MemoryCache()
    decision = clean_decision()
    store(cache, decision, 100.0)
    assert lookup(cache, IDENTITY, "generation-a", request(), 99.0) is None
