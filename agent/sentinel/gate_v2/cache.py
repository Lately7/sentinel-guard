"""Generation-bound cache for immutable Gate v2 scan decisions."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, replace
from typing import Literal, Protocol

from .contract import CONTRACT_VERSION, FileIdentity, FinalDecision, ScanRequest, StageStatus, VerdictCode

log = logging.getLogger(__name__)

LONG_TTL = 30 * 24 * 60 * 60
SHORT_TTL = 60 * 60
MAX_PAYLOAD_BYTES = 256 * 1024


@dataclass(frozen=True)
class GenerationInputs:
    policy_version: str
    contract_version: int
    core_version: str
    analyzer_versions: tuple[tuple[str, str], ...]
    rule_digests: tuple[tuple[str, str], ...]
    known_bad_generation: str
    clamav_generation: str | None
    clamav_state: Literal["verified", "not_installed", "disabled_by_policy", "unavailable"]
    defender_state: Literal["active", "passive", "not_installed", "disabled_by_policy", "unknown"]
    exception_generation: str
    disabled_by_policy: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.clamav_state not in ("verified", "not_installed", "disabled_by_policy", "unavailable"):
            raise ValueError("invalid ClamAV state")
        if self.defender_state not in ("active", "passive", "not_installed", "disabled_by_policy", "unknown"):
            raise ValueError("invalid Defender state")


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def gate_generation(inputs: GenerationInputs) -> str:
    fields = asdict(inputs)
    fields["analyzer_versions"] = sorted(inputs.analyzer_versions)
    fields["rule_digests"] = sorted(inputs.rule_digests)
    fields["disabled_by_policy"] = sorted(inputs.disabled_by_policy)
    return _digest(fields)


def cache_class(decision: FinalDecision) -> Literal["long", "short", "none"]:
    if not decision.cacheable or any(
        result.status in (
            StageStatus.TIMEOUT, StageStatus.CHANGED, StageStatus.CANCELLED,
            StageStatus.UNVERIFIED, StageStatus.ERROR,
        ) or result.coverage.mode == "runtime_partial"
        for result in decision.engine_results
    ):
        return "none"
    if decision.verdict is VerdictCode.MALICIOUS:
        return "long" if decision.accepted_evidence_ids else "none"
    if decision.verdict is VerdictCode.CLEAN:
        return "long" if decision.trusted_clean else "short"
    if decision.verdict is VerdictCode.SUSPICIOUS:
        return "short"
    return "none"


class CacheStore(Protocol):
    def get(self, key: str) -> str | None: ...

    def put(self, key: str, payload: str, expires_at: float) -> None: ...


def cache_key(identity: FileIdentity | None, gate_generation: str) -> str | None:
    if identity is None or not identity.file_id_hex:
        return None
    return _digest({
        "sha256": identity.sha256,
        "volume_serial": identity.volume_serial,
        "file_id_hex": identity.file_id_hex,
        "size": identity.size,
        "mtime_ns": identity.mtime_ns,
        "change_time_ns": identity.change_time_ns,
        "canonical_path": identity.canonical_path,
        "gate_generation": gate_generation,
    })


def store(cache: CacheStore, decision: FinalDecision, now: float) -> None:
    kind = cache_class(decision)
    key = cache_key(decision.identity, decision.gate_generation)
    if kind == "none" or key is None:
        return
    # Action authority depends on current protection and identity, never on a past scan.
    scan = replace(decision, action_decision=None)
    expires_at = now + (LONG_TTL if kind == "long" else SHORT_TTL)
    scan_value = scan.to_dict()
    del scan_value["action_decision"]
    payload = json.dumps({
        "contract_version": CONTRACT_VERSION,
        "key": key,
        "expires_at": expires_at,
        "decision": scan_value,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(payload.encode("utf-8")) <= MAX_PAYLOAD_BYTES:
        try:
            cache.put(key, payload, expires_at)
        except Exception:
            # An unwritable cache only costs a rescan; it must not fail the scan.
            log.warning("scan cache write failed", exc_info=True)


def lookup(
    cache: CacheStore, identity: FileIdentity | None, gate_generation: str,
    request: ScanRequest, now: float,
) -> FinalDecision | None:
    try:
        key = cache_key(identity, gate_generation)
        if key is None or not request.use_cache:
            return None
        payload = cache.get(key)
        if payload is None or len(payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            return None
        value = json.loads(payload)
        if (type(value) is not dict or value.get("contract_version") != CONTRACT_VERSION
                or value.get("key") != key or type(value.get("expires_at")) not in (int, float)
                or value["expires_at"] <= now):
            return None
        scan_value = value["decision"]
        if type(scan_value) is not dict or "action_decision" in scan_value:
            return None
        decision = FinalDecision.from_dict({**scan_value, "action_decision": None})
        if (decision.identity != identity or decision.gate_generation != gate_generation
                or cache_class(decision) == "none" or decision.action_decision is not None):
            return None
        return replace(
            decision, scan_id=request.scan_id, file_id=request.file_id,
            engine_results=tuple(replace(result, file_id=request.file_id) for result in decision.engine_results),
            action_decision=None,
        )
    except Exception:
        # Cache storage and deserialization are both untrusted I/O boundaries.
        return None
