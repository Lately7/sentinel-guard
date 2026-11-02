"""A2: Gate v2 adapters running inside the restricted worker (R13 §2, R13b P4–P5).

Harmless inputs only: the marker rule for on-disk positives, EICAR in memory.
"""

from __future__ import annotations

import os
import time
import zipfile

import pytest

from conftest import EICAR, MARKER

pytestmark = pytest.mark.skipif(os.name != "nt", reason="restricted workers need Windows")

from sentinel.gate_v2.contract import ScanRequest, StageStatus, VerdictCode  # noqa: E402
from sentinel.gate_v2.orchestrator import scan  # noqa: E402
from sentinel.gate_v2.policy import RequiredStages  # noqa: E402
from sentinel.service.workerclient import WorkerAdapter, WorkerSession  # noqa: E402


class Token:
    def __init__(self, value: bool = False) -> None:
        self.value = value

    def cancelled(self) -> bool:
        return self.value


def request(*, path=None, data=None, seconds=30.0, file_id="f") -> ScanRequest:
    return ScanRequest(2, "scan", file_id, path, data, "test", "single_file" if path else "memory",
                       "evidence-v1", "evidence-v1", time.monotonic_ns() + int(seconds * 1e9), None, False)


@pytest.fixture
def session(marker_rule):
    s = WorkerSession(json_packs=((str(marker_rule), marker_rule.read_bytes(), True),))
    yield s
    s.close()


def run(session, req, engines=("core", "json_rules"), cancel=None):
    adapters = [WorkerAdapter(session, e) for e in engines]
    return scan(req, adapters=adapters, stages=RequiredStages(frozenset(engines)),
                gate_generation="test", auto_quarantine=False, cancel=cancel)


def test_marker_file_on_disk_is_found_by_the_worker(session, tmp_path):
    p = tmp_path / "doc.bin"
    p.write_bytes(b"head " + MARKER + b" tail")
    d = run(session, request(path=str(p)))
    assert d.verdict is VerdictCode.MALICIOUS
    assert [r.status for r in d.engine_results] == [StageStatus.COMPLETED, StageStatus.COMPLETED]
    assert session.starts == 1 and session.engines == ["core", "json_rules"]


def test_marker_inside_a_zip_is_found_by_the_worker(session, tmp_path):
    p = tmp_path / "bundle.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", b"hello")
        z.writestr("inner/payload.bin", b"x" + MARKER + b"y")
    d = run(session, request(path=str(p)))
    assert d.verdict is VerdictCode.MALICIOUS
    assert any(e.scope == "member" for r in d.engine_results for e in r.evidence)


def test_eicar_in_memory_is_conclusive_and_marked_as_a_test_file(session):
    d = run(session, request(data=EICAR), engines=("core",))
    assert d.verdict is VerdictCode.MALICIOUS
    assert d.engine_results[0].evidence[0].is_test_file


def test_clean_synthetic_file_is_clean(session, tmp_path):
    p = tmp_path / "notes.txt"
    p.write_bytes(b"nothing to see here\n" * 100)
    d = run(session, request(path=str(p)))
    assert d.verdict is VerdictCode.CLEAN


def test_a_worker_that_died_between_calls_is_replaced(session, tmp_path):
    from sentinel.service import worker as worker_mod

    p = tmp_path / "doc.bin"
    p.write_bytes(b"head " + MARKER + b" tail")
    assert run(session, request(path=str(p))).verdict is VerdictCode.MALICIOUS
    worker_mod._k32.TerminateProcess(session._proc._process, 9)
    session._proc.wait(5)
    d = run(session, request(path=str(p)), engines=("json_rules",))
    assert d.verdict is VerdictCode.MALICIOUS and session.starts == 2


class KillsWorkerOnce:
    """Cancellation token whose first poll terminates the worker mid-call."""

    def __init__(self, session) -> None:
        self.session, self.done = session, False

    def cancelled(self) -> bool:
        if not self.done and self.session._proc is not None:
            from sentinel.service import worker as worker_mod

            worker_mod._k32.TerminateProcess(self.session._proc._process, 9)
            self.done = True
        return False


def test_a_worker_dying_mid_call_is_an_error_never_clean(session, tmp_path):
    p = tmp_path / "notes.txt"
    p.write_bytes(b"nothing to see here")
    d = run(session, request(path=str(p)), engines=("core",), cancel=KillsWorkerOnce(session))
    assert d.engine_results[0].status is StageStatus.ERROR
    assert d.engine_results[0].readiness_code == "WORKER_DIED"
    assert d.verdict is VerdictCode.UNKNOWN and not d.trusted_clean


def test_cancel_and_deadline_are_typed_never_clean(session, tmp_path):
    p = tmp_path / "notes.txt"
    p.write_bytes(b"nothing")
    d = run(session, request(path=str(p)), engines=("core",), cancel=Token(True))
    assert d.verdict is not VerdictCode.CLEAN and not d.trusted_clean
    session.call("init", session._init_args, deadline_ns=time.monotonic_ns() + int(30e9))  # make sure it is up
    late = request(path=str(p), seconds=0.0)
    from sentinel.gate_v2.content import BoundReader

    reader = BoundReader.measure_path(str(p), max_bytes=1 << 20, cancel=Token())
    try:
        r = WorkerAdapter(session, "core").scan_bound(late, reader.identity, Token(), reader)
    finally:
        reader.close()
    assert r.status is StageStatus.TIMEOUT and r.verdict is VerdictCode.UNKNOWN


def test_garbage_or_misbound_worker_output_is_rejected(session, tmp_path, monkeypatch):
    p = tmp_path / "notes.txt"
    p.write_bytes(b"nothing")
    from sentinel.gate_v2.content import BoundReader

    reader = BoundReader.measure_path(str(p), max_bytes=1 << 20, cancel=Token())
    try:
        adapter = WorkerAdapter(session, "core")
        monkeypatch.setattr(session, "call", lambda *a, **k: {"engine_result": {"verdict": "clean"}})
        r = adapter.scan_bound(request(path=str(p)), reader.identity, Token(), reader)
        assert (r.status, r.readiness_code) == (StageStatus.ERROR, "WORKER_BAD_RESULT")
        monkeypatch.undo()
        good = adapter.scan_bound(request(path=str(p)), reader.identity, Token(), reader)
        assert good.status is StageStatus.COMPLETED
        other = good.to_dict() | {"file_id": "someone-else"}
        monkeypatch.setattr(session, "call", lambda *a, **k: {"engine_result": other})
        r = adapter.scan_bound(request(path=str(p)), reader.identity, Token(), reader)
        assert (r.status, r.readiness_code) == (StageStatus.ERROR, "WORKER_RESULT_BINDING")
    finally:
        reader.close()
