"""Pure cache tests; no filesystem scan or temporary directory is needed."""

from dataclasses import replace
import json

from sentinel.gate_v2.cache import (
    LONG_TTL, MAX_PAYLOAD_BYTES, SHORT_TTL, GenerationInputs, cache_class,
    cache_key, gate_generation, lookup, store,
)
from sentinel.gate_v2.contract import (
    ActionCode, ActionDecision, ByteRange, Category, Coverage, EngineResult,
    Evidence, FileIdentity, ScanRequest, StageStatus, Strength, VerdictCode,
)
from sentinel.gate_v2.policy import RequiredStages, decide


class MemoryCache:
    def __init__(self):
        self.rows = {}

    def get(self, key):
        return self.rows.get(key, (None, None))[0]

    def put(self, key, payload, expires_at):
        self.rows[key] = payload, expires_at


def inputs():
    return GenerationInputs(
        "evidence-v1", 2, "core-v1", (("pe", "1"), ("script", "2")),
        (("json_rules", "aaa"), ("yara_x", "bbb")), "hash-1", "db-1",
        "verified", "active", "exceptions-1", (),
    )


def request(scan_id="scan-1", file_id="file-1"):
    return ScanRequest(2, scan_id, file_id, None, b"abc", "test", "memory",
                       "evidence-v1", "legacy-v0", 10**18, None, True)


def identity():
    return FileIdentity("C:/sample", 7, "a" * 32, 3, "b" * 64, 13, 17)


def result(status=StageStatus.COMPLETED, strength=None, *, mode="full"):
    ident = identity()
    span = (ByteRange(0, 3),) if mode == "full" else (ByteRange(0, 2),) if mode == "fixed_partial" else ()
    coverage = Coverage(3, span, mode, 0, 0, 0, 0, (), (), (), "verified")
    evidence = () if strength is None else (Evidence(
        "e-1", "core", "SYNTHETIC", None, Category.MALWARE, strength,
        "outer", None, (ByteRange(0, 1),), "test-rule", None, None, True, "SYNTHETIC",
    ),)
    return EngineResult(2, "core", "file-1", ident, status,
                        VerdictCode.MALICIOUS if strength is Strength.CONCLUSIVE else VerdictCode.UNKNOWN,
                        coverage, evidence, "1", None, None, "READY", 0, 4, None)


def decision(status=StageStatus.COMPLETED, strength=None, *, mode="full", disabled=False):
    stages = RequiredStages(frozenset({"core"}), frozenset({"core"}) if disabled else frozenset())
    return decide((result(status, strength, mode=mode),), request(), "gate-1", stages=stages)


def test_generation_uses_each_input_and_canonical_tuple_order():
    base = inputs()
    digest = gate_generation(base)
    assert gate_generation(replace(base, analyzer_versions=tuple(reversed(base.analyzer_versions)),
                                   rule_digests=tuple(reversed(base.rule_digests)))) == digest
    changes = {
        "policy_version": "other", "contract_version": 3, "core_version": "core-v2",
        "analyzer_versions": (("pe", "2"), ("script", "2")),
        "rule_digests": (("json_rules", "ccc"), ("yara_x", "bbb")),
        "known_bad_generation": "hash-2", "clamav_generation": "db-2",
        "clamav_state": "not_installed", "defender_state": "passive",
        "exception_generation": "exceptions-2", "disabled_by_policy": ("clamav",),
    }
    for field, value in changes.items():
        assert gate_generation(replace(base, **{field: value})) != digest, field


def test_cache_class_covers_decision_table_and_second_lock():
    assert cache_class(decision(strength=Strength.CONCLUSIVE)) == "long"
    assert cache_class(decision()) == "long"
    assert cache_class(decision(strength=Strength.SUPPORTING)) == "short"
    reduced = decision(status=StageStatus.PARTIAL, mode="fixed_partial")
    assert reduced.verdict is VerdictCode.CLEAN and not reduced.trusted_clean
    assert cache_class(reduced) == "short"
    assert cache_class(decision(disabled=True)) == "short"
    assert cache_class(decision(StageStatus.UNAVAILABLE, mode="none", disabled=True)) == "short"
    assert cache_class(decision(StageStatus.ERROR, mode="none")) == "none"
    for status in (StageStatus.TIMEOUT, StageStatus.CHANGED, StageStatus.CANCELLED,
                   StageStatus.UNVERIFIED, StageStatus.ERROR):
        forced = replace(decision(), engine_results=(result(status),))
        assert cache_class(forced) == "none"
    assert cache_class(replace(decision(), engine_results=(result(mode="runtime_partial"),))) == "none"
    assert cache_class(replace(decision(), cacheable=False)) == "none"


def test_cache_hit_rebinds_ids_omits_action_and_never_upgrades_reduced_clean():
    cache = MemoryCache()
    original = decision(status=StageStatus.PARTIAL, mode="fixed_partial")
    action = ActionDecision(2, "legacy-v0", ActionCode.NONE, "NO_ACTION", (),
                            "file-1", original.identity, None, False)
    store(cache, replace(original, action_decision=action), 100)
    key = cache_key(original.identity, original.gate_generation)
    payload, expiry = cache.rows[key]
    assert expiry == 100 + SHORT_TTL
    assert "action_decision" not in payload
    hit = lookup(cache, original.identity, original.gate_generation,
                 request("scan-2", "file-2"), 101)
    assert hit is not None
    assert hit.scan_id == "scan-2" and hit.file_id == "file-2"
    assert all(item.file_id == "file-2" for item in hit.engine_results)
    assert hit.action_decision is None and hit.verdict == original.verdict
    assert hit.reason_codes == original.reason_codes
    assert hit.accepted_evidence_ids == original.accepted_evidence_ids
    assert hit.policy_scope == "reduced" and not hit.trusted_clean


def test_long_ttl_generation_recheck_and_all_misses():
    cache = MemoryCache()
    original = decision()
    store(cache, original, 100)
    key = cache_key(original.identity, original.gate_generation)
    payload, expiry = cache.rows[key]
    assert expiry == 100 + LONG_TTL
    assert lookup(cache, original.identity, original.gate_generation, request(), 101) is not None
    for state in ("not_installed", "disabled_by_policy", "unavailable"):
        generation = gate_generation(replace(inputs(), clamav_state=state))
        assert lookup(cache, original.identity, generation, request(), 101) is None
    for state in ("passive", "not_installed", "disabled_by_policy", "unknown"):
        generation = gate_generation(replace(inputs(), defender_state=state))
        assert lookup(cache, original.identity, generation, request(), 101) is None
    for clamav_state, defender_state in (("not_installed", "passive"),
                                          ("disabled_by_policy", "disabled_by_policy")):
        generation = gate_generation(replace(inputs(), clamav_state=clamav_state,
                                             defender_state=defender_state))
        current = replace(original, gate_generation=generation)
        store(cache, current, 100)
        assert lookup(cache, current.identity, generation, request(), 101) is not None
        assert lookup(cache, current.identity, gate_generation(inputs()), request(), 101) is None
    assert lookup(cache, replace(original.identity, mtime_ns=18), original.gate_generation, request(), 101) is None
    assert lookup(cache, original.identity, original.gate_generation, request(), expiry) is None
    assert cache_key(None, "gate-1") is None
    assert cache_key(replace(original.identity, file_id_hex=None), "gate-1") is None
    for bad in ("{", "x" * (MAX_PAYLOAD_BYTES + 1)):
        cache.rows[key] = bad, expiry
        assert lookup(cache, original.identity, original.gate_generation, request(), 101) is None
    value = json.loads(payload)
    value["decision"]["identity"]["sha256"] = "c" * 64
    cache.rows[key] = json.dumps(value), expiry
    assert lookup(cache, original.identity, original.gate_generation, request(), 101) is None
    value = json.loads(payload)
    value["contract_version"] = 99
    cache.rows[key] = json.dumps(value), expiry
    assert lookup(cache, original.identity, original.gate_generation, request(), 101) is None


def test_unknown_and_oversized_payload_are_not_stored():
    cache = MemoryCache()
    store(cache, decision(StageStatus.ERROR, mode="none"), 100)
    assert not cache.rows
    oversized = replace(decision(), reason_codes=tuple("r" * 128 for _ in range(64)))
    # Repeated bounded reasons alone fit; many bounded evidence and stage fields can exceed the cap.
    huge_results = tuple(replace(result(), engine_id=f"engine{i}",
                                 evidence=tuple(replace(result(strength=Strength.SUPPORTING).evidence[0],
                                                        engine_id=f"engine{i}", evidence_id=f"e{j}",
                                                        raw_name="x" * 512) for j in range(64)))
                         for i in range(64))
    oversized = replace(oversized, engine_results=huge_results)
    store(cache, oversized, 100)
    assert not cache.rows
