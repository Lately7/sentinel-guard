"""Regression checks for service failures and the user-level answers."""

from __future__ import annotations

import logging
import threading
import time
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from sentinel import config, nativehost, overview_ui
from sentinel.service import backend as backend_module, bridge, workerclient
from sentinel.service.backend import ProductBackend, _Job
from sentinel.service.rescan import Download, MemoryDownloadStore, RescanQueue
from sentinel.service.workerclient import WorkerFailure, WorkerSession
from sentinel.gate_v2.contract import StageStatus


def test_download_unknown_uses_local_scan_but_failed_job_remains_error(tmp_path, monkeypatch):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"ordinary text")
    local = SimpleNamespace(label="clean", to_dict=lambda **kwargs: {"label": "clean"})
    host = nativehost.Host(SimpleNamespace(), config.Settings(), SimpleNamespace(
        scan_download=lambda *args: {"state": "done", "verdict": {"label": "unknown"}, "label": "unknown"}))
    host._scanner = SimpleNamespace(scan_file=lambda *args, **kwargs: local)
    calls = []
    monkeypatch.setattr(nativehost.urlintel, "check", lambda *args: None)
    monkeypatch.setattr(nativehost, "escalate_origin", lambda *args: None)
    monkeypatch.setattr(nativehost, "act_on", lambda *args: calls.append(True) or {"label": "clean", "quarantined": False})
    monkeypatch.setattr(nativehost, "top_reason", lambda *args: "clean")
    assert host.on_scan_download({"path": str(path)})["label"] == "clean"
    assert calls == [True]
    host.lease.scan_download = lambda *args: {"state": "failed", "code": "SCAN_FAILED"}
    with pytest.raises(nativehost.BadRequest):
        host.on_scan_download({"path": str(path)})


def test_worker_start_backoff_logs_only_changed_failure(monkeypatch, caplog):
    now = [100.0]
    monkeypatch.setattr(workerclient.time, "monotonic", lambda: now[0])
    session = WorkerSession()
    starts = []
    failure_code = ["INSTALL_INTEGRITY"]

    def fail(deadline_ns):
        starts.append(True)
        raise WorkerFailure(StageStatus.UNAVAILABLE, failure_code[0])

    monkeypatch.setattr(session, "_start", fail)
    with caplog.at_level(logging.WARNING):
        for _ in range(20):
            with pytest.raises(WorkerFailure):
                session.call("scan", {}, deadline_ns=time.monotonic_ns() + 1_000_000_000)
        now[0] += 61
        with pytest.raises(WorkerFailure):
            session.call("scan", {}, deadline_ns=time.monotonic_ns() + 1_000_000_000)
    assert len(starts) == 2
    assert session.last_failure == "INSTALL_INTEGRITY"
    assert caplog.text.count("worker did not start") == 1
    failure_code[0] = "START_REFUSED"
    now[0] += 61
    with caplog.at_level(logging.WARNING), pytest.raises(WorkerFailure):
        session.call("scan", {}, deadline_ns=time.monotonic_ns() + 1_000_000_000)
    assert session.last_failure == "START_REFUSED"
    assert caplog.text.count("worker did not start") == 2
    monkeypatch.setattr(session, "_start", lambda deadline_ns: setattr(session, "_proc", SimpleNamespace(wait=lambda timeout: None)))
    monkeypatch.setattr(session, "_send", lambda *args, **kwargs: {})
    now[0] += 61
    session.call("scan", {}, deadline_ns=time.monotonic_ns() + 1_000_000_000)
    assert session.last_failure == ""


def backend_stub(failure: str = "") -> ProductBackend:
    backend = object.__new__(ProductBackend)
    backend.scanner = SimpleNamespace(isolation=SimpleNamespace(failure=lambda: failure), gate_id=lambda: "new")
    backend._lock = threading.Lock()
    backend._later = []
    backend._worker_down_skipped = 0
    backend.db = SimpleNamespace(add_event=lambda *args: None, quarantine_items=lambda: [],
                                 get_meta=lambda *args: "0", allow_version=lambda: "0")
    backend.barrier = SimpleNamespace(current=lambda: 1, action=nullcontext)
    backend.settings = config.Settings()
    backend.observers = None
    backend._asked_lane = SimpleNamespace(stalled=0)
    backend._observed_lane = SimpleNamespace(stalled=0)
    return backend


def test_observed_worker_failure_counts_without_retry_or_event(tmp_path):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"ordinary text")
    backend = backend_stub("INSTALL_INTEGRITY")
    events = []
    backend.db.add_event = lambda *args: events.append(args)
    job = _Job("j", str(path), "journal", None, "", None)
    job.result = {"verdict": {"label": "unknown", "scan_result": {"reason_codes": ["ENGINE_INCOMPLETE"]}}}
    backend._after_observed(job)
    assert backend._later == [] and events == []
    assert backend.status()["worker_down_skipped"] == 1
    backend._later.append((0.0, str(path), "journal", 1))
    backend._retry_due()
    assert len(backend._later) == 1
    backend._gave_up(job)
    assert "quét" in events[0][3].lower() and "liên tục bị giữ" not in events[0][3]


def test_first_rule_check_queues_old_download_and_rescan_updates_generation(monkeypatch):
    backend = backend_stub()
    backend._rule_generation = None
    backend.rescans = RescanQueue(MemoryDownloadStore())
    old = Download(1, 2, "C:/plain.txt", "a" * 64, "old", time.time())
    backend.rescans.remember(old)
    offered = []
    monkeypatch.setattr(backend, "observe", lambda path, reason, fresh=False: offered.append((path, reason, fresh)) or True)
    backend.rescan_on_new_rules()
    assert offered == [(old.path, "rescan", True)]
    seen = SimpleNamespace(volume_serial=1, file_id_hex="2", sha256=old.sha256, canonical_path=old.path)
    verdict = SimpleNamespace(decision=SimpleNamespace(identity=seen, trusted_clean=True, engine_results=(), reason_codes=()),
                              label="clean", to_dict=lambda **kwargs: {"label": "clean"})
    monkeypatch.setattr(backend_module, "act_on", lambda *args, **kwargs: {"label": "clean", "quarantined": False})
    monkeypatch.setattr(backend_module, "top_reason", lambda *args: "clean")
    backend._finish(_Job("j", old.path, "rescan", None, "", None), verdict, None)
    assert backend.rescans.store.get(old.identity).gate_generation == "new"
    backend.scanner.gate_id = lambda: "newer"
    incomplete = SimpleNamespace(decision=SimpleNamespace(identity=seen, trusted_clean=False, engine_results=(), reason_codes=()),
                                 label="unknown", to_dict=lambda **kwargs: {"label": "unknown"})
    monkeypatch.setattr(backend_module, "act_on", lambda *args, **kwargs: {"label": "unknown", "quarantined": False})
    backend._finish(_Job("j2", old.path, "rescan", None, "", None), incomplete, None)
    assert backend.rescans.store.get(old.identity).gate_generation == "new"
    backend.scanner.gate_id = lambda: "new"
    backend.rescan_on_new_rules()
    assert len(offered) == 1


def test_unknown_worker_result_adds_no_observed_file_event(monkeypatch):
    backend = backend_stub("INSTALL_INTEGRITY")
    monkeypatch.setattr(backend_module, "act_on", lambda *args, **kwargs: pytest.fail("unknown must not be acted on"))
    monkeypatch.setattr(backend_module, "top_reason", lambda *args: "worker unavailable")
    verdict = SimpleNamespace(decision=None, label="unknown", to_dict=lambda **kwargs: {"label": "unknown"})
    result = backend._finish(_Job("j", "C:/plain.txt", "journal", None, "", None), verdict, None)
    assert result["label"] == "unknown"


def test_permanent_incomplete_coverage_has_no_retry_and_reports_coverage(tmp_path):
    path = tmp_path / "plain.zip"
    path.write_bytes(b"harmless")
    backend = backend_stub()
    events = []
    backend.db.add_event = lambda *args: events.append(args)
    job = _Job("j", str(path), "journal", None, "", None)
    job.result = {"verdict": {"label": "unknown", "scan_result": {"reason_codes": ["INCOMPLETE_COVERAGE"]}}}
    backend._after_observed(job)
    assert not backend._later
    assert len(events) == 1 and "đầy đủ" in events[0][3]
    job.result["verdict"]["scan_result"]["reason_codes"] = ["ENGINE_TIMEOUT", "INCOMPLETE_COVERAGE"]
    backend._after_observed(job)
    assert len(backend._later) == 1


def test_hash_hit_stays_local_unless_service_reports_same_evidence():
    hit = SimpleNamespace(evidence_id="hit", signature_id="KNOWN_BAD_HASH", detail_code="KNOWN_BAD_HASH",
                          source_id="sentinel-core")
    decision = SimpleNamespace(accepted_evidence_ids=("hit",), engine_results=(SimpleNamespace(engine_id="core", evidence=(hit,)),))
    verdict = SimpleNamespace(decision=decision, sha256="a" * 64)
    done = {"state": "done", "engines": ["core"], "verdict": {"sha256": verdict.sha256, "findings": []}}
    assert bridge._left_to_us(verdict, done)
    done["verdict"]["findings"] = [{"rule": "hash.known_bad"}]
    assert not bridge._left_to_us(verdict, done)
    done["verdict"]["sha256"] = "b" * 64
    assert bridge._left_to_us(verdict, done)


def test_overview_worker_failure_is_attention():
    app = SimpleNamespace(realtime=SimpleNamespace(running=True), db=SimpleNamespace(
        feed_status=lambda: [{"updated": 100.0}], get_meta=lambda *args: "100"),
        engine_status=SimpleNamespace(snapshot=SimpleNamespace(clamav_status="ready")))
    state = overview_ui.protection_state(app, now=101.0, service_status={"worker_failure": "INSTALL_INTEGRITY"})
    assert state.level == "attention"
    assert "quét" in state.detail.lower() and "bảo vệ" in state.detail.lower()


def test_overview_status_poll_does_not_wait_on_pipe():
    entered = threading.Event()
    release = threading.Event()

    def blocked_status():
        entered.set()
        release.wait(2)
        return {"worker_failure": "INSTALL_INTEGRITY"}

    view = object.__new__(overview_ui.Overview)
    view.app = SimpleNamespace(lease=SimpleNamespace(status=blocked_status), ui=lambda *args: None, refresh=lambda: None)
    view._service_status = None
    view._service_checked = float("-inf")
    view._service_pending = False
    view._service_lock = threading.Lock()
    try:
        start = time.monotonic()
        view._poll_service()
        assert time.monotonic() - start < 0.5
        assert entered.wait(1)
        assert view._service_pending
    finally:
        release.set()


def test_a_local_detection_stands_when_the_service_saw_other_bytes():
    hit = SimpleNamespace(evidence_id="hit", signature_id="yara.x", detail_code="YARA_MATCH", source_id="rules")
    decision = SimpleNamespace(accepted_evidence_ids=("hit",),
                               engine_results=(SimpleNamespace(engine_id="yara_x", evidence=(hit,)),))
    verdict = SimpleNamespace(decision=decision, sha256="a" * 64)
    done = {"state": "done", "engines": ["core", "yara_x"], "verdict": {"sha256": "b" * 64, "findings": []}}
    assert bridge._left_to_us(verdict, done)
    done["verdict"]["sha256"] = "a" * 64
    assert not bridge._left_to_us(verdict, done)


def test_status_arriving_after_the_window_closed_goes_through_the_app_not_the_widgets():
    queued = []
    view = object.__new__(overview_ui.Overview)
    view.app = SimpleNamespace(lease=SimpleNamespace(status=lambda: {}), ui=queued.append, refresh=lambda: None)
    view._service_lock = threading.Lock()
    view._service_pending = False
    view._service_checked = float("-inf")
    view._service_status = None
    view._poll_service()
    deadline = time.monotonic() + 5
    while not queued and time.monotonic() < deadline:
        time.sleep(0.01)
    assert queued == [view.app.refresh]


def test_a_cloud_placeholder_is_neither_retried_nor_reported_file_by_file(tmp_path):
    path = tmp_path / "cloud.docm"
    path.write_bytes(b"stand-in")
    backend = backend_stub()
    events = []
    backend.db.add_event = lambda *args: events.append(args)
    job = _Job("j", str(path), "journal", None, "", None)
    job.result = {"verdict": {"label": "unknown", "scan_result": {"reason_codes": ["CLOUD_PLACEHOLDER"]}}}
    backend._after_observed(job)
    assert backend._later == [] and events == []
