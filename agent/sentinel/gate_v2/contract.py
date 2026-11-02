"""Immutable Gate v2 wire contracts.

All free text is rejected above 512 characters, paths above 4096, and reason
or evidence lists above 64 entries. Codes and identifiers are capped at 128.
No truncation occurs, so serialisation preserves accepted values exactly.
"""

from __future__ import annotations

import base64
import re
import types
from dataclasses import dataclass, fields, is_dataclass
from enum import StrEnum
from typing import Any, Literal, Protocol, Union, get_args, get_origin, get_type_hints

CONTRACT_VERSION = 2
EVENT_VERSION = 1
EVIDENCE_POLICY_VERSION = "evidence-v1"
LEGACY_POLICY_VERSION = "legacy-v0"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_ID = re.compile(r"[0-9a-fA-F]{32}\Z")
_EVENT_CODE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


class ContractError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def _text(value: str | None, name: str, limit: int = 512) -> None:
    if value is not None:
        _require(type(value) is str and len(value) <= limit, f"INVALID_{name.upper()}")


def _event_token(value: str | None, name: str) -> None:
    if value is not None:
        _require(type(value) is str and bool(_EVENT_CODE.fullmatch(value)) and not _SHA256.fullmatch(value), f"INVALID_{name.upper()}")


def _nonnegative(value: int, name: str) -> None:
    _require(type(value) is int and value >= 0, f"INVALID_{name.upper()}")


def _list(value: tuple[Any, ...], name: str, limit: int = 64) -> None:
    _require(type(value) is tuple and len(value) <= limit, f"INVALID_{name.upper()}")


def _ranges(value: tuple[ByteRange, ...], size: int | None = None) -> None:
    _list(value, "ranges", 4096)
    previous = 0
    for item in value:
        _require(isinstance(item, ByteRange), "INVALID_RANGE")
        _require(item.start >= previous, "UNSORTED_OR_OVERLAPPING_RANGES")
        if size is not None:
            _require(item.end <= size, "OUT_OF_BOUNDS_RANGE")
        previous = item.end


def _encode(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$bytes": base64.b64encode(value).decode("ascii")}
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value):
        return {field.name: _encode(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_encode(item) for item in value]
    return value


def _decode(hint: Any, value: Any) -> Any:
    origin = get_origin(hint)
    args = get_args(hint)
    if origin in (types.UnionType, Union):
        if value is None and type(None) in args:
            return None
        for candidate in args:
            if candidate is type(None):
                continue
            try:
                return _decode(candidate, value)
            except ContractError:
                pass
        raise ContractError("INVALID_FIELD_TYPE")
    if origin is Literal:
        _require(value in args and any(type(value) is type(arg) for arg in args), "INVALID_LITERAL")
        return value
    if origin is tuple:
        _require(type(value) is list, "INVALID_FIELD_TYPE")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_decode(args[0], item) for item in value)
        _require(len(value) == len(args), "INVALID_TUPLE")
        return tuple(_decode(arg, item) for arg, item in zip(args, value))
    if isinstance(hint, type) and issubclass(hint, StrEnum):
        try:
            _require(type(value) is str, "INVALID_ENUM")
            return hint(value)
        except ValueError as exc:
            raise ContractError("INVALID_ENUM") from exc
    if isinstance(hint, type) and is_dataclass(hint):
        return hint.from_dict(value)
    if hint is bytes:
        _require(type(value) is dict and set(value) == {"$bytes"}, "INVALID_BYTES")
        try:
            decoded = base64.b64decode(value["$bytes"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ContractError("INVALID_BYTES") from exc
        _require(base64.b64encode(decoded).decode("ascii") == value["$bytes"], "INVALID_BYTES")
        return decoded
    _require(type(value) is hint, "INVALID_FIELD_TYPE")
    return value


class WireValue:
    def to_dict(self) -> dict[str, Any]:
        return _encode(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Any:
        _require(type(value) is dict, "INVALID_OBJECT")
        names = {field.name for field in fields(cls)}
        _require(set(value) == names, "INVALID_FIELDS")
        hints = get_type_hints(cls)
        return cls(**{name: _decode(hints[name], value[name]) for name in names})


class StageStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    UNVERIFIED = "unverified"
    CHANGED = "changed"


class VerdictCode(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class Strength(StrEnum):
    CONCLUSIVE = "conclusive"
    STRONG = "strong"
    SUPPORTING = "supporting"
    CONTEXT = "context"
    COVERAGE = "coverage"


class Category(StrEnum):
    MALWARE = "malware"
    PUA = "pua"
    RISKWARE = "riskware"
    STRUCTURE = "structure"
    ORIGIN = "origin"
    HEALTH = "health"


class ActionCode(StrEnum):
    NONE = "none"
    NOTIFY = "notify"
    REVIEW = "review"
    QUARANTINE = "quarantine"
    RETRY = "retry"


@dataclass(frozen=True)
class ByteRange(WireValue):
    start: int
    end: int

    def __post_init__(self) -> None:
        _nonnegative(self.start, "range_start")
        _nonnegative(self.end, "range_end")
        _require(self.start <= self.end, "INVALID_RANGE")


@dataclass(frozen=True)
class FileIdentity(WireValue):
    canonical_path: str | None
    volume_serial: int | None
    file_id_hex: str | None
    size: int
    sha256: str
    change_time_ns: int | None
    mtime_ns: int | None

    def __post_init__(self) -> None:
        _text(self.canonical_path, "path", 4096)
        _nonnegative(self.size, "size")
        _require(type(self.sha256) is str and bool(_SHA256.fullmatch(self.sha256)), "INVALID_SHA256")
        if self.file_id_hex is not None:
            _require(type(self.file_id_hex) is str and bool(_HEX_ID.fullmatch(self.file_id_hex)), "INVALID_FILE_ID_HEX")
        for name in ("volume_serial", "change_time_ns", "mtime_ns"):
            value = getattr(self, name)
            if value is not None:
                _nonnegative(value, name)


@dataclass(frozen=True)
class Coverage(WireValue):
    input_size: int
    inspected: tuple[ByteRange, ...]
    mode: Literal["full", "fixed_partial", "runtime_partial", "none"]
    objects_seen: int
    objects_inspected: int
    objects_opaque: int
    objects_omitted: int
    object_reasons: tuple[str, ...]
    parser_states: tuple[tuple[str, str], ...]
    limits_hit: tuple[str, ...]
    certainty: Literal["verified", "declared", "unknown"]

    def __post_init__(self) -> None:
        _nonnegative(self.input_size, "input_size")
        _require(self.mode in ("full", "fixed_partial", "runtime_partial", "none"), "INVALID_COVERAGE_MODE")
        _require(self.certainty in ("verified", "declared", "unknown"), "INVALID_CERTAINTY")
        _ranges(self.inspected, self.input_size)
        for name in ("objects_seen", "objects_inspected", "objects_opaque", "objects_omitted"):
            _nonnegative(getattr(self, name), name)
        _require(self.objects_inspected + self.objects_opaque + self.objects_omitted <= self.objects_seen, "INVALID_OBJECT_COUNTS")
        for name in ("object_reasons", "parser_states", "limits_hit"):
            values = getattr(self, name)
            _list(values, name)
            for item in values:
                if name == "parser_states":
                    _require(type(item) is tuple and len(item) == 2, "INVALID_PARSER_STATE")
                    for part in item:
                        _text(part, "parser_state", 128)
                else:
                    _text(item, name, 128)
        if self.mode == "full":
            _require(self.inspected == ((ByteRange(0, self.input_size),) if self.input_size else ()), "FALSE_FULL_COVERAGE")
            _require(not (self.objects_opaque or self.objects_omitted or self.limits_hit), "FALSE_FULL_COVERAGE")


@dataclass(frozen=True)
class Evidence(WireValue):
    evidence_id: str
    engine_id: str
    signature_id: str | None
    raw_name: str | None
    category: Category
    strength: Strength
    scope: Literal["outer", "member", "origin", "system"]
    member_path: str | None
    ranges: tuple[ByteRange, ...]
    source_id: str
    source_digest: str | None
    correlation_group: str | None
    verified: bool
    detail_code: str
    is_test_file: bool = False

    def __post_init__(self) -> None:
        for name in ("evidence_id", "engine_id", "signature_id", "source_id", "source_digest", "correlation_group", "detail_code"):
            _text(getattr(self, name), name, 128)
        _text(self.raw_name, "raw_name")
        _text(self.member_path, "member_path")
        _require(isinstance(self.category, Category) and isinstance(self.strength, Strength), "INVALID_ENUM")
        _require(self.scope in ("outer", "member", "origin", "system"), "INVALID_SCOPE")
        _require(type(self.verified) is bool and type(self.is_test_file) is bool, "INVALID_BOOLEAN")
        _require(self.strength is not Strength.CONCLUSIVE or self.verified, "UNVERIFIED_CONCLUSIVE")
        _ranges(self.ranges)


@dataclass(frozen=True)
class ScanError(WireValue):
    code: str
    operation: str
    message: str
    retryable: bool

    def __post_init__(self) -> None:
        _text(self.code, "error_code", 128)
        _text(self.operation, "operation", 128)
        _text(self.message, "message")
        _require(type(self.retryable) is bool, "INVALID_BOOLEAN")


@dataclass(frozen=True)
class EngineResult(WireValue):
    contract_version: Literal[2]
    engine_id: str
    file_id: str
    identity: FileIdentity
    status: StageStatus
    verdict: VerdictCode
    coverage: Coverage
    evidence: tuple[Evidence, ...]
    engine_version: str | None
    db_version: str | None
    generation_digest: str | None
    readiness_code: str
    started_monotonic_ns: int
    duration_ms: int
    error: ScanError | None

    def __post_init__(self) -> None:
        _require(self.contract_version == CONTRACT_VERSION, "UNKNOWN_CONTRACT_VERSION")
        for name in ("engine_id", "file_id", "engine_version", "db_version", "generation_digest", "readiness_code"):
            _text(getattr(self, name), name, 128)
        _require(isinstance(self.identity, FileIdentity) and isinstance(self.coverage, Coverage), "INVALID_FIELD_TYPE")
        _require(isinstance(self.status, StageStatus) and isinstance(self.verdict, VerdictCode), "INVALID_ENUM")
        _nonnegative(self.started_monotonic_ns, "started_monotonic_ns")
        _nonnegative(self.duration_ms, "duration_ms")
        _list(self.evidence, "evidence")
        _require(all(isinstance(item, Evidence) and item.engine_id == self.engine_id for item in self.evidence), "INVALID_EVIDENCE_ENGINE")
        _require(self.error is None or isinstance(self.error, ScanError), "INVALID_FIELD_TYPE")
        _require(self.status is not StageStatus.COMPLETED or self.error is None, "COMPLETED_WITH_ERROR")
        _require(self.verdict is not VerdictCode.CLEAN or self.status is StageStatus.COMPLETED, "NONCOMPLETED_CLEAN")
        _ranges(self.coverage.inspected, self.identity.size)
        for item in self.evidence:
            _ranges(item.ranges, self.identity.size)
        if self.status is StageStatus.COMPLETED:
            _require(bool(self.identity.sha256), "MISSING_IDENTITY")


@dataclass(frozen=True)
class ScanRequest(WireValue):
    contract_version: Literal[2]
    scan_id: str
    file_id: str
    path: str | None
    data: bytes | None
    source: Literal["cli", "watcher", "download", "on_demand", "test"]
    profile: Literal["smart", "deep", "single_file", "memory"]
    policy_version: str
    action_policy_version: str
    deadline_monotonic_ns: int
    protection_generation: int | None
    use_cache: bool
    include_paths_in_events: bool = False

    def __post_init__(self) -> None:
        _require(self.contract_version == CONTRACT_VERSION, "UNKNOWN_CONTRACT_VERSION")
        for name in ("scan_id", "file_id", "policy_version", "action_policy_version"):
            _text(getattr(self, name), name, 128)
        _require(self.policy_version == EVIDENCE_POLICY_VERSION, "UNKNOWN_POLICY_VERSION")
        _require(self.action_policy_version in (EVIDENCE_POLICY_VERSION, LEGACY_POLICY_VERSION), "UNKNOWN_ACTION_POLICY")
        _text(self.path, "path", 4096)
        _require((self.path is None) != (self.data is None), "INVALID_REQUEST_INPUT")
        _require(self.data is None or type(self.data) is bytes, "INVALID_BYTES")
        _require(self.source in ("cli", "watcher", "download", "on_demand", "test"), "INVALID_SOURCE")
        _require(self.profile in ("smart", "deep", "single_file", "memory"), "INVALID_PROFILE")
        _nonnegative(self.deadline_monotonic_ns, "deadline_monotonic_ns")
        if self.protection_generation is not None:
            _nonnegative(self.protection_generation, "protection_generation")
        _require(type(self.use_cache) is bool and type(self.include_paths_in_events) is bool, "INVALID_BOOLEAN")


@dataclass(frozen=True)
class FinalDecision(WireValue):
    contract_version: Literal[2]
    scan_id: str
    file_id: str
    identity: FileIdentity | None
    verdict: VerdictCode
    trusted_clean: bool
    policy_scope: Literal["full", "reduced"]
    reason_codes: tuple[str, ...]
    accepted_evidence_ids: tuple[str, ...]
    engine_results: tuple[EngineResult, ...]
    cacheable: bool
    gate_generation: str
    duration_ms: int

    def __post_init__(self) -> None:
        _require(self.contract_version == CONTRACT_VERSION, "UNKNOWN_CONTRACT_VERSION")
        for name in ("scan_id", "file_id", "gate_generation"):
            _text(getattr(self, name), name, 128)
        _require(self.identity is None or isinstance(self.identity, FileIdentity), "INVALID_FIELD_TYPE")
        _require(isinstance(self.verdict, VerdictCode), "INVALID_ENUM")
        _require(type(self.trusted_clean) is bool and type(self.cacheable) is bool, "INVALID_BOOLEAN")
        _require(self.policy_scope in ("full", "reduced"), "INVALID_POLICY_SCOPE")
        for name in ("reason_codes", "accepted_evidence_ids"):
            values = getattr(self, name)
            _list(values, name)
            for item in values:
                _text(item, name, 128)
        _list(self.engine_results, "engine_results")
        _require(all(isinstance(item, EngineResult) and item.file_id == self.file_id for item in self.engine_results), "MISMATCHED_FILE_ID")
        ids = [item.engine_id for item in self.engine_results]
        _require(len(ids) == len(set(ids)), "DUPLICATE_ENGINE_ID")
        _nonnegative(self.duration_ms, "duration_ms")
        _require(not self.trusted_clean or (self.verdict is VerdictCode.CLEAN and self.policy_scope == "full"), "FALSE_TRUSTED_CLEAN")
        _require(not self.cacheable or self.verdict not in (VerdictCode.UNKNOWN,), "FALSE_CACHEABLE")


@dataclass(frozen=True)
class ActionDecision(WireValue):
    contract_version: Literal[2]
    action_policy_version: str
    action: ActionCode
    reason_code: str
    evidence_ids: tuple[str, ...]
    file_id: str
    expected_identity: FileIdentity | None
    protection_generation: int | None
    requires_revalidation: bool

    def __post_init__(self) -> None:
        _require(self.contract_version == CONTRACT_VERSION, "UNKNOWN_CONTRACT_VERSION")
        for name in ("action_policy_version", "reason_code", "file_id"):
            _text(getattr(self, name), name, 128)
        _require(self.action_policy_version in (EVIDENCE_POLICY_VERSION, LEGACY_POLICY_VERSION), "UNKNOWN_ACTION_POLICY")
        _require(isinstance(self.action, ActionCode), "INVALID_ENUM")
        _list(self.evidence_ids, "evidence_ids")
        for item in self.evidence_ids:
            _text(item, "evidence_id", 128)
        _require(self.expected_identity is None or isinstance(self.expected_identity, FileIdentity), "INVALID_FIELD_TYPE")
        if self.protection_generation is not None:
            _nonnegative(self.protection_generation, "protection_generation")
        _require(type(self.requires_revalidation) is bool, "INVALID_BOOLEAN")


@dataclass(frozen=True)
class ScanEvent(WireValue):
    event_version: Literal[1]
    scan_id: str
    file_id: str | None
    sequence: int
    stage: str
    state: Literal["started", "finished", "skipped", "error", "cancelled"]
    duration_ms: int | None
    result_code: str
    counters_delta: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        _require(self.event_version == EVENT_VERSION, "UNKNOWN_EVENT_VERSION")
        for name in ("scan_id", "file_id", "stage", "result_code"):
            _event_token(getattr(self, name), name)
        _nonnegative(self.sequence, "sequence")
        if self.duration_ms is not None:
            _nonnegative(self.duration_ms, "duration_ms")
        _require(self.state in ("started", "finished", "skipped", "error", "cancelled"), "INVALID_EVENT_STATE")
        _list(self.counters_delta, "counters_delta")
        for key, amount in self.counters_delta:
            _event_token(key, "counter_code")
            _require(type(amount) is int, "INVALID_COUNTER")


class CancellationToken(Protocol):
    def cancelled(self) -> bool: ...


class EngineAdapter(Protocol):
    engine_id: str

    def readiness(self) -> str: ...
    def scan(self, request: ScanRequest, identity: FileIdentity, cancel: CancellationToken) -> EngineResult: ...
