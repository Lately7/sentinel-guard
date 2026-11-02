from __future__ import annotations

import os
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
from sentinel.gate_v2 import identity as identity_module

from sentinel.gate_v2.contract import (
    ActionCode, ByteRange, Category, Coverage, EngineResult, Evidence, FileIdentity,
    ScanRequest, StageStatus, Strength, VerdictCode,
)
from sentinel.gate_v2.events import EventStream
from sentinel.gate_v2.identity import measure, measure_bytes, revalidate
from sentinel.gate_v2.orchestrator import ScanState, scan, scan_many


def test_imports_share_canonical_contract_types() -> None:
    from sentinel.gate_v2 import contract
    assert ScanRequest is contract.ScanRequest
    assert EngineResult is contract.EngineResult


class Token:
    def __init__(self) -> None:
        self.value = False

    def cancelled(self) -> bool:
        return self.value


def request(path: str | None = None, data: bytes | None = None, file_id: str = "f") -> ScanRequest:
    return ScanRequest(2, "scan", file_id, path, data if path is None else None,
                       "test", "single_file", "evidence-v1", "evidence-v1",
                       time.monotonic_ns() + 10_000_000_000, None, False)


def completed(engine: str, req: ScanRequest, ident: FileIdentity, *, hit: bool = False, weak: bool = False) -> EngineResult:
    coverage = Coverage(ident.size, (ByteRange(0, ident.size),) if ident.size else (),
                        "full", 0, 0, 0, 0, (), (), (), "verified")
    evidence = ()
    if hit or weak:
        evidence = (Evidence(f"{engine}.hit", engine, "marker", None, Category.MALWARE,
                             Strength.SUPPORTING if weak else Strength.CONCLUSIVE,
                             "outer", None, (ByteRange(0, min(1, ident.size)),),
                             "test", None, None, True, "MARKER"),)
    return EngineResult(2, engine, req.file_id, ident, StageStatus.COMPLETED,
                        VerdictCode.SUSPICIOUS if weak else VerdictCode.MALICIOUS if hit else VerdictCode.CLEAN,
                        coverage, evidence, None, None, None, "OK", 1, 0, None)


class Adapter:
    def __init__(self, engine_id: str, behavior=None, *, reopens_path: bool = False) -> None:
        self.engine_id = engine_id
        self.behavior = behavior
        self.reopens_path = reopens_path
        self.calls: list[str] = []

    def readiness(self) -> str:
        return "READY"

    def scan(self, req: ScanRequest, ident: FileIdentity, cancel: Token) -> EngineResult:
        self.calls.append(req.file_id)
        if self.behavior:
            return self.behavior(req, ident, cancel)
        return completed(self.engine_id, req, ident)


def test_identity_swap_rename_link_and_failures(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"A" * 8)
    original = measure(str(path))
    assert original.ok and original.identity
    old_mtime = original.identity.mtime_ns
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"B" * 8)
    os.utime(replacement, ns=(old_mtime, old_mtime))
    os.replace(replacement, path)
    assert revalidate(str(path), original.identity, rehash=True).code == "CHANGED"
    current = measure(str(path)).identity
    assert current
    same_metadata_old_hash = replace(current, sha256=original.identity.sha256)
    assert revalidate(str(path), same_metadata_old_hash, rehash=False).ok
    assert revalidate(str(path), same_metadata_old_hash, rehash=True).code == "CHANGED"
    renamed = tmp_path / "renamed.bin"
    path.rename(renamed)
    assert measure(str(renamed)).identity.file_id_hex == current.file_id_hex
    link = tmp_path / "linked.bin"
    try:
        os.link(renamed, link)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    assert measure(str(link)).identity.file_id_hex == current.file_id_hex
    assert measure(str(tmp_path)).code == "NOT_REGULAR"
    assert measure(str(tmp_path / "missing")).code == "UNREADABLE"
    assert measure_bytes(b"abc", max_bytes=2).code == "TOO_LARGE"


def test_identity_changed_and_cancelled_between_chunks(tmp_path: Path) -> None:
    path = tmp_path / "chunks"
    path.write_bytes(b"A" * 64)
    def change(_: int) -> None:
        with path.open("r+b") as stream:
            stream.seek(0)
            stream.write(b"B")
    assert measure(str(path), chunk_size=8, between_chunks=change).code == "CHANGED"
    token = Token()
    assert measure(str(path), chunk_size=8, cancel=token,
                   between_chunks=lambda _: setattr(token, "value", True)).code == "CANCELLED"


def test_identity_in_place_rewrite_with_restored_mtime(tmp_path: Path) -> None:
    path = tmp_path / "same-file.bin"
    path.write_bytes(b"AAAA")
    original = measure(str(path)).identity
    assert original is not None
    with path.open("r+b") as stream:
        stream.write(b"BBBB")
    assert original.mtime_ns is not None
    os.utime(path, ns=(original.mtime_ns, original.mtime_ns))
    assert measure(str(path)).identity.file_id_hex == original.file_id_hex
    assert revalidate(str(path), original, rehash=True).code == "CHANGED"


@pytest.mark.skipif(os.name != "nt", reason="Win32 bindings only exist on Windows")
def test_win32_identity_bindings_are_module_scoped() -> None:
    assert identity_module.FileBasicInfo.__module__ == identity_module.__name__
    assert identity_module._get_file_information.argtypes is not None
    assert identity_module._get_final_path.argtypes is not None


def test_long_unicode_path(tmp_path: Path) -> None:
    root = tmp_path
    try:
        for index in range(4):
            root = root / ("tên_" + str(index) + "x" * 64)
            root.mkdir()
        path = root / "mẫu.bin"
        path.write_bytes(b"safe")
    except OSError as exc:
        pytest.skip(f"OS refuses long path: {exc}")
    assert measure(str(path)).ok


def test_orchestrator_rejects_errors_and_wrong_binding() -> None:
    req = request(data=b"safe")
    cases = [
        lambda r, i, c: (_ for _ in ()).throw(RuntimeError("C:/private")),
        lambda r, i, c: replace(completed("one", r, i), file_id="wrong"),
        lambda r, i, c: replace(completed("one", r, i), identity=replace(i, sha256="a" * 64)),
        lambda r, i, c: replace(completed("other", r, i), engine_id="other"),
    ]
    for behavior in cases:
        value = scan(req, adapters=[Adapter("one", behavior)], gate_generation="gen", auto_quarantine=True)
        assert value.verdict is VerdictCode.UNKNOWN and not value.trusted_clean
        assert value.engine_results[0].status in (StageStatus.ERROR, StageStatus.CHANGED)
        assert "private" not in str(value.to_dict())


def test_deadline_cancel_conclusive_and_weak() -> None:
    req = request(data=b"safe")
    first = Adapter("one", lambda r, i, c: completed("one", r, i, hit=True))
    rest = [Adapter("two"), Adapter("three")]
    stream = EventStream("scan")
    value = scan(req, adapters=[first, *rest], gate_generation="gen", auto_quarantine=True, emit=stream)
    assert value.verdict is VerdictCode.MALICIOUS
    assert [x.status for x in value.engine_results] == [StageStatus.COMPLETED, StageStatus.SKIPPED, StageStatus.SKIPPED]
    assert value.action_decision is not None
    assert not rest[0].calls
    terminal = stream.snapshot().terminal
    assert [event.stage for event in terminal] == ["one", "action", "file"]
    assert [event.stage for event in stream.snapshot().progress if event.state == "skipped"] == ["two", "three"]
    assert terminal[0].result_code == "DETECTION"
    weak = Adapter("one", lambda r, i, c: completed("one", r, i, weak=True))
    value = scan(req, adapters=[weak, Adapter("two")], gate_generation="gen", auto_quarantine=True)
    assert [x.status for x in value.engine_results] == [StageStatus.COMPLETED] * 2
    token = Token()
    def cancel_second(r, i, c):
        token.value = True
        return completed("two", r, i)
    value = scan(req, adapters=[Adapter("one"), Adapter("two", cancel_second), Adapter("three"), Adapter("four")],
                 cancel=token, gate_generation="gen", auto_quarantine=True)
    assert value.verdict is VerdictCode.UNKNOWN
    assert [x.status for x in value.engine_results][1:] == [StageStatus.COMPLETED, StageStatus.CANCELLED, StageStatus.CANCELLED]
    token.value = False
    value = scan(req, adapters=[first, Adapter("two", cancel_second), Adapter("three")],
                 cancel=token, gate_generation="gen", auto_quarantine=True, skip_after_conclusive=False)
    assert value.verdict is VerdictCode.MALICIOUS
    expired = replace(req, deadline_monotonic_ns=0)
    value = scan(expired, adapters=[Adapter("one"), Adapter("two")], gate_generation="gen", auto_quarantine=True)
    assert [x.status for x in value.engine_results] == [StageStatus.TIMEOUT] * 2
    ticks = iter((1, 5, 5, 5))
    active = Adapter("one")
    value = scan(replace(req, deadline_monotonic_ns=4), adapters=[active, Adapter("two")],
                 gate_generation="gen", auto_quarantine=True, clock=lambda: next(ticks))
    assert active.calls == ["f"]
    assert [x.status for x in value.engine_results] == [StageStatus.COMPLETED, StageStatus.TIMEOUT]


def test_returned_conclusive_hit_survives_stage_cancellation() -> None:
    req = request(data=b"safe")
    token = Token()
    def hit_then_cancel(r, i, c):
        token.value = True
        return completed("two", r, i, hit=True)
    value = scan(req, adapters=[Adapter("one"), Adapter("two", hit_then_cancel), Adapter("three")],
                 cancel=token, gate_generation="gen", auto_quarantine=True)
    assert value.verdict is VerdictCode.MALICIOUS
    assert [item.status for item in value.engine_results] == [
        StageStatus.COMPLETED, StageStatus.COMPLETED, StageStatus.CANCELLED]
    assert value.engine_results[1].evidence


def test_returned_result_survives_deadline_for_later_stages() -> None:
    req = replace(request(data=b"safe"), deadline_monotonic_ns=4)
    ticks = iter((1, 5, 5, 5))
    value = scan(req, adapters=[Adapter("one", lambda r, i, c: completed("one", r, i, hit=True)),
                                Adapter("two")], gate_generation="gen", auto_quarantine=True,
                 clock=lambda: next(ticks))
    assert value.verdict is VerdictCode.MALICIOUS
    assert [item.status for item in value.engine_results] == [StageStatus.COMPLETED, StageStatus.TIMEOUT]


def test_action_reads_auto_setting_and_stop_generation_after_stages() -> None:
    req = replace(request(data=b"safe"), protection_generation=7)
    hit = Adapter("one", lambda r, i, c: completed("one", r, i, hit=True))
    disabled = scan(req, adapters=[hit], gate_generation="gen", auto_quarantine=False)
    assert (disabled.action_decision.action, disabled.action_decision.reason_code) == (
        ActionCode.NOTIFY, "AUTO_DISABLED")
    generation = [7]
    def stop_during_stage(r, i, c):
        generation[0] = 8
        return completed("one", r, i, hit=True)
    stopped = scan(req, adapters=[Adapter("one", stop_during_stage)], gate_generation="gen",
                   auto_quarantine=True, current_protection_generation=lambda: generation[0])
    assert (stopped.action_decision.action, stopped.action_decision.reason_code) == (
        ActionCode.NONE, "PROTECTION_STOPPED")


def test_legacy_weak_name_revalidates_before_quarantine(tmp_path: Path) -> None:
    path = tmp_path / "legacy.bin"
    path.write_bytes(b"AAAA")
    req = replace(request(path=str(path)), action_policy_version="legacy-v0")
    def weak_and_rewrite(r, i, c):
        result = completed("clamav", r, i, weak=True)
        evidence = replace(result.evidence[0], raw_name="Weak.Example")
        with path.open("r+b") as stream:
            stream.write(b"BBBB")
        assert i.mtime_ns is not None
        os.utime(path, ns=(i.mtime_ns, i.mtime_ns))
        return replace(result, evidence=(evidence,))
    value = scan(req, adapters=[Adapter("clamav", weak_and_rewrite)], gate_generation="gen",
                 auto_quarantine=True)
    assert value.verdict is VerdictCode.SUSPICIOUS
    assert (value.action_decision.action, value.action_decision.reason_code) == (
        ActionCode.NONE, "CHANGED_BEFORE_ACTION")


def test_path_stage_swap_is_changed(tmp_path: Path) -> None:
    path = tmp_path / "safe.bin"
    path.write_bytes(b"AAAA")
    def swap(r, i, c):
        path.write_bytes(b"BBBB")
        return completed("path", r, i, hit=True)
    value = scan(request(path=str(path)), adapters=[Adapter("path", swap, reopens_path=True)], gate_generation="gen", auto_quarantine=True)
    assert value.engine_results[0].status is StageStatus.CHANGED
    assert value.verdict is VerdictCode.UNKNOWN


@pytest.mark.parametrize("workers", [2, 4])
def test_parallel_files_preserve_binding_and_order(workers: int) -> None:
    requests = [request(data=f"safe-{n}".encode(), file_id=f"f{n}") for n in range(30)]
    adapters = [Adapter("one"), Adapter("two"), Adapter("three")]
    values = scan_many(requests, adapters=adapters, workers=workers, gate_generation="gen", auto_quarantine=True)
    assert [v.file_id for v in values] == [r.file_id for r in requests]
    for value in values:
        assert [r.engine_id for r in value.engine_results] == ["one", "two", "three"]
        assert all(r.file_id == value.file_id and r.identity == value.identity for r in value.engine_results)


def test_scan_many_waits_for_slow_terminal_consumer() -> None:
    requests = [request(data=b"safe", file_id=f"f{n}") for n in range(12)]
    stream = EventStream("scan", terminal_capacity=3)
    stop = threading.Event()
    def consume() -> None:
        while not stop.is_set():
            stream.drain_terminal()
            time.sleep(0.01)
    consumer = threading.Thread(target=consume, daemon=True)
    consumer.start()
    try:
        values = scan_many(requests, adapters=[Adapter("one")], gate_generation="gen",
                           auto_quarantine=True, emit=stream, workers=4)
    finally:
        stop.set()
        consumer.join(timeout=2)
    assert len(values) == len(requests)
    assert all(value.verdict is VerdictCode.CLEAN for value in values)
    assert all(value.engine_results[0].status is StageStatus.COMPLETED for value in values)


def test_scan_many_cancel_while_admission_waits() -> None:
    requests = [request(data=b"safe", file_id=f"f{n}") for n in range(8)]
    stream = EventStream("scan", terminal_capacity=3)
    token = Token()
    result: list[tuple] = []
    def run() -> None:
        result.append(scan_many(requests, adapters=[Adapter("one")], gate_generation="gen",
                                auto_quarantine=True, emit=stream, cancel=token, workers=4))
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    deadline = time.monotonic() + 2
    while len(stream.snapshot().terminal) < 2 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert len(stream.snapshot().terminal) == 2
    token.value = True
    worker.join(timeout=3)
    assert not worker.is_alive(), "admission wait did not notice cancellation"
    assert len(result) == 1
    assert result[0][0].verdict is VerdictCode.CLEAN
    assert all(value.verdict is VerdictCode.UNKNOWN and "CANCELLED" in value.reason_codes
               for value in result[0][1:])


def test_state_machine_illegal_transitions() -> None:
    machine = ScanState()
    with pytest.raises(ValueError):
        machine.advance("deciding")
    for state in ("opening", "hashing", "stages", "deciding", "complete"):
        machine.advance(state)
    with pytest.raises(ValueError):
        machine.advance("opening")


def test_events_stress_admission_sequence_and_privacy() -> None:
    stream = EventStream("scan", progress_capacity=8, terminal_capacity=4)
    assert stream.admit("f", terminal_slots=4)
    done = threading.Event()
    def produce() -> None:
        for n in range(500_000):
            stream.publish("f", "core", "started", "RUNNING")
            stream.count("bytes", 1)
        done.set()
    thread = threading.Thread(target=produce, daemon=True)
    thread.start()
    thread.join(timeout=30)
    assert done.is_set(), "publisher blocked on paused consumer"
    snapshot = stream.snapshot()
    assert len(snapshot.progress) <= 8 and snapshot.coalesced > 0
    assert dict(snapshot.counters)["bytes"] == 500_000
    assert not stream.admit("g", terminal_slots=1)
    for n in range(4):
        stream.publish("f", "core", "finished", f"CODE{n}", terminal=True)
    stream.release("f")
    assert not stream.admit("g", terminal_slots=1)
    records = stream.drain_terminal(4)
    assert [event.sequence for event in records] == sorted(event.sequence for event in records)
    assert stream.admit("g", terminal_slots=1)
    assert all("path" not in item.to_dict() and "sha256" not in item.to_dict() for item in records)
