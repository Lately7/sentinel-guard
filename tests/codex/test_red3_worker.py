"""RED3: in-process probes of the worker protocol trust boundary."""

from __future__ import annotations

import io
import queue
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from sentinel.gate_v2.contract import (
    ByteRange, Coverage, EngineResult, FileIdentity, ScanRequest, StageStatus,
    VerdictCode,
)
from sentinel.gate_v2.orchestrator import scan
from sentinel.gate_v2.rules import JsonRulesAdapter
from sentinel.service.workerclient import WorkerAdapter, WorkerFailure, WorkerSession


# A crafted file that controls its worker can flood valid replies and exhaust service memory.
def test_unsolicited_worker_frames_have_bounded_parent_buffer() -> None:
    from sentinel.service.protocol import write_frame

    wire = io.BytesIO()
    for rid in range(1_000):
        write_frame(wire, {"id": rid, "ok": True, "result": {"pad": "x" * 256}})
    proc = SimpleNamespace(stdout=io.BytesIO(wire.getvalue()))
    replies: queue.Queue[dict | None] = queue.Queue()
    pump = threading.Thread(target=WorkerSession._pump, args=(proc, replies), daemon=True)
    pump.start()
    try:
        until = time.monotonic() + 0.5
        while replies.qsize() <= 16 and pump.is_alive() and time.monotonic() < until:
            time.sleep(0.01)
        assert replies.qsize() <= 16
    finally:
        until = time.monotonic() + 2
        while pump.is_alive() and time.monotonic() < until:
            try:
                replies.get(timeout=0.01)
            except queue.Empty:
                pass
        pump.join(timeout=0.1)


# A worker that stops reading stdin can hold a service scan beyond its deadline.
def test_worker_pipe_write_obeys_scan_deadline() -> None:
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    failures: list[BaseException] = []

    class BlockedInput:
        def write(self, data: bytes) -> int:
            entered.set()
            release.wait(2)
            return len(data)

        def flush(self) -> None:
            pass

    class FakeProcess:
        stdin = BlockedInput()

        def kill(self) -> None:
            release.set()

    session = WorkerSession()
    session._proc = FakeProcess()  # type: ignore[assignment]

    def send() -> None:
        try:
            session._send("scan", {}, time.monotonic_ns() + 50_000_000, None)
        except BaseException as exc:
            failures.append(exc)
        finally:
            finished.set()

    thread = threading.Thread(target=send, daemon=True)
    thread.start()
    try:
        assert entered.wait(1)
        assert finished.wait(0.3)
        assert len(failures) == 1
        assert isinstance(failures[0], WorkerFailure)
        assert failures[0].status is StageStatus.TIMEOUT
    finally:
        release.set()
        thread.join(timeout=1)


# A file-controlled worker can certify clean coverage without reading the measured handle.
def test_worker_clean_claim_requires_proof_of_stage_read(tmp_path: Path, marker_rule: Path) -> None:
    from conftest import MARKER

    path = tmp_path / "marker.bin"
    path.write_bytes(MARKER)
    request = ScanRequest(2, "red3", "file", str(path), None, "test", "single_file",
                          "evidence-v1", "evidence-v1", time.monotonic_ns() + 5_000_000_000,
                          None, False)
    real = scan(request, adapters=[JsonRulesAdapter(((str(marker_rule), marker_rule.read_bytes(), True),))],
                gate_generation="red3", auto_quarantine=False)
    assert real.verdict is VerdictCode.MALICIOUS

    class LyingSession:
        def call(self, op, args, *, deadline_ns, cancel=None, handle_from=None):
            assert op == "scan" and handle_from is not None
            identity = FileIdentity.from_dict(args["identity"])
            req = ScanRequest.from_dict(args["request"])
            coverage = Coverage(identity.size, (ByteRange(0, identity.size),), "full",
                                0, 0, 0, 0, (), (), (), "verified")
            result = EngineResult(2, "json_rules", req.file_id, identity, StageStatus.COMPLETED,
                                  VerdictCode.CLEAN, coverage, (), None, None, None, "READY",
                                  time.monotonic_ns(), 0, None)
            return {"engine_result": result.to_dict()}

    claimed = scan(request, adapters=[WorkerAdapter(LyingSession(), "json_rules")],
                   gate_generation="red3", auto_quarantine=False)
    assert claimed.verdict is not VerdictCode.CLEAN
    assert not claimed.trusted_clean
