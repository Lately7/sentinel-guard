"""Sequential per-file stages with bounded file-level concurrency."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Callable, Iterable

from . import identity
from .content import BoundReader, ContentError
from .contract import (
    CONTRACT_VERSION, ActionCode, ActionDecision, CancellationToken, ContractError, Coverage,
    EngineAdapter, EngineResult, FileIdentity, FinalDecision, ScanError,
    ScanRequest, StageStatus, VerdictCode,
)
from .events import EventStream
from .policy import RequiredStages, decide, should_auto_quarantine

Clock = Callable[[], int]


class ScanState:
    _NEXT = {
        "queued": {"opening", "cancelled"},
        "opening": {"hashing", "unknown", "cancelled"},
        "hashing": {"stages", "unknown", "cancelled"},
        "stages": {"deciding", "cancelled"},
        "deciding": {"complete", "cancelled"},
        "complete": set(), "cancelled": set(), "unknown": set(),
    }

    def __init__(self) -> None:
        self.state = "queued"

    def advance(self, state: str) -> None:
        if state not in self._NEXT[self.state]:
            raise ValueError(f"illegal transition: {self.state} -> {state}")
        self.state = state


@dataclass(frozen=True)
class _NeverCancel:
    def cancelled(self) -> bool:
        return False


def _empty_coverage(size: int) -> Coverage:
    return Coverage(size, (), "none", 0, 0, 0, 0, (), (), (), "unknown")


def _synthetic(
    adapter: EngineAdapter, request: ScanRequest, measured: FileIdentity,
    status: StageStatus, code: str, started: int, duration_ms: int = 0,
) -> EngineResult:
    return EngineResult(CONTRACT_VERSION, adapter.engine_id, request.file_id,
                        measured, status, VerdictCode.UNKNOWN, _empty_coverage(measured.size),
                        (), None, None, None, code, started, duration_ms,
                        ScanError(code, "scan", code, status in (StageStatus.ERROR, StageStatus.TIMEOUT, StageStatus.CHANGED))
                        if status in (StageStatus.ERROR, StageStatus.TIMEOUT, StageStatus.CHANGED) else None)


def _unknown(request: ScanRequest, generation: str, code: str, auto_quarantine: bool,
             measured: FileIdentity | None = None) -> FinalDecision:
    decision = FinalDecision(CONTRACT_VERSION, request.scan_id, request.file_id, measured,
                             VerdictCode.UNKNOWN, False, "full", (code,), (), (), False,
                             generation, 0)
    action = should_auto_quarantine(
        decision, policy_version=request.action_policy_version,
        auto_quarantine=auto_quarantine, protection_generation=request.protection_generation,
        current_protection_generation=request.protection_generation,
        identity_reverified=False,
    )
    return replace(decision, action_decision=action)


def _publish(
    emit: EventStream | Callable[..., object] | None, file_id: str,
    stage: str, state: str, code: str, *, duration_ms: int | None = None,
    terminal: bool = False,
) -> None:
    if emit is None:
        return
    if isinstance(emit, EventStream):
        emit.publish(file_id, stage, state, code, duration_ms=duration_ms, terminal=terminal)
    else:
        emit(file_id, stage, state, code, duration_ms=duration_ms, terminal=terminal)


def scan(
    request: ScanRequest, *, adapters: Iterable[EngineAdapter],
    stages: RequiredStages | None = None, cancel: CancellationToken | None = None,
    gate_generation: str, auto_quarantine: bool,
    current_protection_generation: Callable[[], int | None] | None = None,
    emit: EventStream | Callable[..., object] | None = None,
    clock: Clock = time.monotonic_ns, max_bytes: int = 512 * 1024 * 1024,
    skip_after_conclusive: bool = True,
    _admitted: bool = False,
) -> FinalDecision:
    ordered = tuple(adapters)
    ids = tuple(item.engine_id for item in ordered)
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate adapters")
    required = stages or RequiredStages(frozenset(ids))
    token = cancel or _NeverCancel()
    machine = ScanState()
    reader: BoundReader | None = None
    admitted = _admitted or not isinstance(emit, EventStream) or emit.admit(request.file_id, terminal_slots=len(ordered) + 2)
    if not admitted:
        return _unknown(request, gate_generation, "ADMISSION_FULL", auto_quarantine)
    try:
        if not ordered or not required.required:
            value = _unknown(request, gate_generation, "NO_ENABLED_STAGES", auto_quarantine)
            _publish(emit, request.file_id, "action", "finished", value.action_decision.action.value.upper(), terminal=True)
            _publish(emit, request.file_id, "file", "error", "NO_ENABLED_STAGES", terminal=True)
            return value
        if token.cancelled():
            machine.advance("cancelled")
            value = _unknown(request, gate_generation, "CANCELLED", auto_quarantine)
            _publish(emit, request.file_id, "action", "finished", value.action_decision.action.value.upper(), terminal=True)
            _publish(emit, request.file_id, "file", "cancelled", "CANCELLED", terminal=True)
            return value
        machine.advance("opening")
        _publish(emit, request.file_id, "identity", "started", "OPENING")
        machine.advance("hashing")
        bound = any(callable(getattr(item, "scan_bound", None)) for item in ordered)
        if bound and request.path is not None:
            try:
                reader = BoundReader.measure_path(request.path, max_bytes=max_bytes, cancel=token)
                measured_result = identity.IdentityResult(reader.identity, "OK")
            except ContentError as exc:
                measured_result = identity.IdentityResult(None, exc.code)
            except OSError:
                measured_result = identity.IdentityResult(None, "UNREADABLE")
        else:
            measured_result = (identity.measure(request.path, max_bytes=max_bytes, cancel=token)
                               if request.path is not None else identity.measure_bytes(request.data or b"", max_bytes=max_bytes, cancel=token))
        if not measured_result.ok:
            machine.advance("cancelled" if measured_result.code == "CANCELLED" else "unknown")
            value = _unknown(request, gate_generation, measured_result.code, auto_quarantine)
            _publish(emit, request.file_id, "action", "finished", value.action_decision.action.value.upper(), terminal=True)
            _publish(emit, request.file_id, "file", "cancelled" if measured_result.code == "CANCELLED" else "error",
                     measured_result.code, terminal=True)
            return value
        measured = measured_result.identity
        assert measured is not None
        if bound and reader is None:
            reader = BoundReader.from_bytes(request.data or b"", measured)
        _publish(emit, request.file_id, "identity", "finished", "OK")
        machine.advance("stages")
        results: list[EngineResult] = []
        stop: StageStatus | None = None
        for adapter in ordered:
            start = clock()
            if stop is None:
                if token.cancelled():
                    stop = StageStatus.CANCELLED
                elif start >= request.deadline_monotonic_ns:
                    stop = StageStatus.TIMEOUT
                elif skip_after_conclusive and results:
                    try:
                        prior = decide(tuple(results), request, gate_generation, stages=RequiredStages(frozenset(item.engine_id for item in results)))
                        if prior.verdict is VerdictCode.MALICIOUS:
                            stop = StageStatus.SKIPPED
                    except ContractError:
                        pass
            if stop is not None:
                code = "CONCLUSIVE_HIT" if stop is StageStatus.SKIPPED else stop.value.upper()
                result = _synthetic(adapter, request, measured, stop, code, start)
            else:
                _publish(emit, request.file_id, adapter.engine_id, "started", "RUNNING")
                try:
                    if getattr(adapter, "reopens_path", False) and request.path is not None:
                        checked = identity.revalidate(request.path, measured, rehash=True, max_bytes=max_bytes, cancel=token)
                        if not checked.ok:
                            result = _synthetic(adapter, request, measured, StageStatus.CHANGED, checked.code, start)
                        else:
                            result = adapter.scan(request, measured, token)
                    else:
                        scan_bound = getattr(adapter, "scan_bound", None)
                        result = (scan_bound(request, measured, token, reader) if callable(scan_bound)
                                  else adapter.scan(request, measured, token))
                    if not isinstance(result, EngineResult):
                        result = _synthetic(adapter, request, measured, StageStatus.ERROR, "INVALID_RESULT", start)
                except Exception:
                    # Engine exception text may contain paths or raw output.
                    result = _synthetic(adapter, request, measured, StageStatus.ERROR, "ADAPTER_ERROR", start)
                elapsed = max(0, (clock() - start) // 1_000_000)
                if result.engine_id != adapter.engine_id or result.file_id != request.file_id:
                    result = _synthetic(adapter, request, measured, StageStatus.ERROR, "RESULT_BINDING", start, elapsed)
                elif result.identity != measured:
                    result = _synthetic(adapter, request, measured, StageStatus.CHANGED, "RESULT_IDENTITY", start, elapsed)
                elif getattr(adapter, "reopens_path", False) and request.path is not None:
                    checked = identity.revalidate(request.path, measured, rehash=True, max_bytes=max_bytes)
                    if not checked.ok:
                        result = _synthetic(adapter, request, measured, StageStatus.CHANGED, checked.code, start, elapsed)
                if token.cancelled():
                    stop = StageStatus.CANCELLED
                elif clock() >= request.deadline_monotonic_ns:
                    stop = StageStatus.TIMEOUT
            results.append(result)
            state = ("skipped" if result.status is StageStatus.SKIPPED else
                     "cancelled" if result.status is StageStatus.CANCELLED else
                     "error" if result.status in (StageStatus.ERROR, StageStatus.TIMEOUT, StageStatus.CHANGED) else "finished")
            _publish(emit, request.file_id, adapter.engine_id, state,
                     "DETECTION" if result.evidence else
                     "CONCLUSIVE_HIT" if result.status is StageStatus.SKIPPED else result.status.value.upper(),
                     duration_ms=result.duration_ms,
                     terminal=bool(result.evidence) or result.status in (
                         StageStatus.ERROR, StageStatus.TIMEOUT, StageStatus.CHANGED,
                         StageStatus.CANCELLED, StageStatus.UNVERIFIED, StageStatus.UNAVAILABLE))
        machine.advance("deciding")
        try:
            decision = decide(tuple(results), request, gate_generation, stages=required)
        except ContractError as exc:
            decision = replace(_unknown(request, gate_generation, exc.code, auto_quarantine, measured), engine_results=tuple(results))
        current_generation = (current_protection_generation() if current_protection_generation is not None
                              else request.protection_generation)
        action: ActionDecision = should_auto_quarantine(
            decision, policy_version=request.action_policy_version,
            auto_quarantine=auto_quarantine, protection_generation=request.protection_generation,
            current_protection_generation=current_generation,
            identity_reverified=True,
        )
        if action.action is ActionCode.QUARANTINE and request.path is not None:
            if not identity.revalidate(request.path, measured, rehash=True, max_bytes=max_bytes).ok:
                action = should_auto_quarantine(
                    decision, policy_version=request.action_policy_version,
                    auto_quarantine=auto_quarantine, protection_generation=request.protection_generation,
                    current_protection_generation=current_generation,
                    identity_reverified=False,
                )
        decision = replace(decision, action_decision=action)
        _publish(emit, request.file_id, "action", "finished", action.action.value.upper(), terminal=True)
        was_cancelled = token.cancelled() and decision.verdict is not VerdictCode.MALICIOUS
        machine.advance("cancelled" if was_cancelled else "complete")
        _publish(emit, request.file_id, "file", "cancelled" if was_cancelled else "finished",
                 "CANCELLED" if was_cancelled else decision.verdict.value.upper(), terminal=True)
        return decision
    finally:
        if reader is not None:
            reader.close()
        if isinstance(emit, EventStream):
            emit.release(request.file_id)


def scan_many(
    requests: Iterable[ScanRequest], *, adapters: Iterable[EngineAdapter],
    stages: RequiredStages | None = None, cancel: CancellationToken | None = None,
    gate_generation: str, auto_quarantine: bool,
    current_protection_generation: Callable[[], int | None] | None = None,
    emit: EventStream | Callable[..., object] | None = None,
    clock: Clock = time.monotonic_ns, workers: int = 2,
    max_bytes: int = 512 * 1024 * 1024,
    skip_after_conclusive: bool = True,
) -> tuple[FinalDecision, ...]:
    if not 1 <= workers <= 4:
        raise ValueError("workers must be between 1 and 4")
    ordered_adapters = tuple(adapters)
    def scan_admitted(request: ScanRequest) -> FinalDecision:
        admitted = False
        if isinstance(emit, EventStream):
            admitted = emit.wait_for_admission(request.file_id, terminal_slots=len(ordered_adapters) + 2,
                                               cancel=cancel)
            if not admitted:
                return _unknown(request, gate_generation, "CANCELLED", auto_quarantine)
        return scan(request, adapters=ordered_adapters, stages=stages, cancel=cancel,
                    gate_generation=gate_generation, auto_quarantine=auto_quarantine,
                    current_protection_generation=current_protection_generation,
                    emit=emit, clock=clock, max_bytes=max_bytes,
                    skip_after_conclusive=skip_after_conclusive, _admitted=admitted)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_admitted, request) for request in requests]
        return tuple(future.result() for future in futures)
