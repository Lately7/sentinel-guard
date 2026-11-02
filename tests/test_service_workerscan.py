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
from sentinel.service import workerclient  # noqa: E402
from sentinel.service.workerclient import WorkerAdapter, WorkerFailure, WorkerSession  # noqa: E402


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
    assert session.starts == 1 and session.engines == ["core", "json_rules", "lnk", "signer"]


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


class Capture:
    def __init__(self) -> None:
        self.args: dict = {}

    def call(self, op, args, *, deadline_ns, cancel=None, handle_from=None):
        self.args = args
        raise WorkerFailure(StageStatus.ERROR, "STOP_HERE")


def test_the_worker_learns_the_file_name_but_not_where_it_is(tmp_path):
    # R15-1: it was told the whole path twice (request and identity), although
    # R13b P5 gives it only the measured handle. The name is what core's
    # deceptive-name check needs.
    p = tmp_path / "doc.bin"
    p.write_bytes(b"nothing")
    capture = Capture()
    run(capture, request(path=str(p)), engines=("core",))
    assert capture.args["request"]["path"] == "doc.bin"
    assert capture.args["identity"]["canonical_path"] is None
    assert tmp_path.name not in str(capture.args)


def test_the_measured_identity_comes_back_with_its_path(session, tmp_path):
    p = tmp_path / "doc.bin"
    p.write_bytes(b"nothing")
    d = run(session, request(path=str(p)), engines=("core",))
    assert d.engine_results[0].status is StageStatus.COMPLETED
    assert d.engine_results[0].identity.canonical_path == str(p.resolve())


def test_a_busy_session_does_not_outlast_the_deadline_or_a_cancel():
    # R15-7: the wait for the session lock ignored both.
    s = WorkerSession()
    s._lock.acquire()
    try:
        began = time.monotonic()
        with pytest.raises(WorkerFailure) as late:
            s.call("scan", {}, deadline_ns=time.monotonic_ns() + 100_000_000)
        with pytest.raises(WorkerFailure) as stopped:
            s.call("scan", {}, deadline_ns=time.monotonic_ns() + 5_000_000_000, cancel=Token(True))
    finally:
        s._lock.release()
    assert late.value.status is StageStatus.TIMEOUT and stopped.value.status is StageStatus.CANCELLED
    assert time.monotonic() - began < 1


class MuteWorker:
    """Starts, then never answers."""

    def __init__(self) -> None:
        import threading

        self.stdin = __import__("io").BytesIO()
        self.dead = threading.Event()

    class _Out:
        def __init__(self, dead) -> None:
            self.dead = dead

        def read(self, n):
            self.dead.wait(10)
            return b""

    @property
    def stdout(self):
        return self._Out(self.dead)

    def wait(self, timeout):
        return None

    def kill(self):
        self.dead.set()


def test_worker_start_is_bounded_by_the_callers_deadline(monkeypatch):
    # R15-7: start-up used its own 30 s budget.
    monkeypatch.setattr(workerclient.worker_mod, "launch", lambda *a, **k: MuteWorker())
    monkeypatch.setattr(workerclient.worker_mod, "bootstrap", lambda *a: ["python"])
    began = time.monotonic()
    with pytest.raises(WorkerFailure):
        WorkerSession().call("scan", {}, deadline_ns=time.monotonic_ns() + 200_000_000)
    assert time.monotonic() - began < 2


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
