"""Regressions for quiet worker recovery, file-input rescans, and event retention."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel import config, indicators
from sentinel.db import Database
from sentinel.engine.scanner import Scanner
from sentinel.engine.signatures import SignatureEngine
from sentinel.service import backend as backend_module
from sentinel.service.backend import ProductBackend
from sentinel.service.rescan import Download
from sentinel.service.workerclient import Isolation, WorkerSession


def test_probe_waits_for_retry_and_skips_a_busy_session(monkeypatch: pytest.MonkeyPatch) -> None:
    session = WorkerSession()
    isolation = Isolation()
    isolation.session = session
    started: list[int] = []

    def start(deadline_ns: int) -> None:
        started.append(deadline_ns)
        assert isolation.failure() == "launch failed"
        session._proc = SimpleNamespace()

    monkeypatch.setattr(session, "_start", start)
    session.last_failure = "launch failed"
    session._failed_start_at = time.monotonic()
    assert isolation.probe() is False
    session._failed_start_at -= 61
    session._lock.acquire()
    try:
        assert isolation.probe() is False
    finally:
        session._lock.release()
    assert started == []
    assert isolation.probe() is True
    assert len(started) == 1 and session.last_failure == ""


def test_failed_probe_restarts_only_after_another_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    session = WorkerSession()
    isolation = Isolation()
    isolation.session = session
    attempts: list[int] = []

    def fail(deadline_ns: int) -> None:
        attempts.append(deadline_ns)
        raise OSError("launch refused")

    monkeypatch.setattr(session, "_start", fail)
    session.last_failure = "earlier failure"
    session._failed_start_at = time.monotonic() - 61
    assert isolation.probe() is False
    assert session.last_failure == "launch refused"
    assert isolation.probe() is False and len(attempts) == 1


def test_watch_runs_one_probe_off_thread_and_catches_up() -> None:
    backend = object.__new__(ProductBackend)
    backend._stop = SimpleNamespace(wait=lambda delay: False)
    backend._lock = threading.Lock()
    backend._worker_down_owed = True
    backend._asked_lane = SimpleNamespace(sweep=lambda: None)
    backend._observed_lane = SimpleNamespace(sweep=lambda: None)
    backend._retry_due = lambda: None
    backend._probe_lock = threading.Lock()
    backend._last_probe_at = float("-inf")
    entered, release = threading.Event(), threading.Event()
    failure = ["launch failed"]
    calls: list[int] = []

    def probe() -> bool:
        calls.append(1)
        entered.set()
        release.wait(2)
        failure[0] = ""
        return True

    backend.scanner = SimpleNamespace(isolation=SimpleNamespace(failure=lambda: failure[0], probe=probe))
    owed: list[int] = []
    backend.observers = SimpleNamespace(owe=lambda: owed.append(1))

    def tick() -> None:
        waits = iter((False, True))
        backend._stop = SimpleNamespace(wait=lambda delay: next(waits))
        backend._watch()

    began = time.monotonic()
    tick()
    assert entered.wait(1) and time.monotonic() - began < 1
    tick()
    assert calls == [1] and owed == []
    release.set()
    deadline = time.monotonic() + 2
    while failure[0] and time.monotonic() < deadline:
        time.sleep(0.01)
    tick()
    assert owed == [1]


def test_rescan_key_changes_for_file_inputs_not_host_publish(
    db: Database, scanner: Scanner, monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProductBackend(db, config.Settings(), scanner)
    offered: list[str] = []
    monkeypatch.setattr(backend, "observe", lambda path, reason, fresh=False: offered.append(path) or True)
    baseline = backend._file_rescan_id()
    old_gate = scanner.gate_id()
    backend.rescans.remember(Download(1, 2, "C:/ordinary.bin", "a" * 64, baseline, time.time()))
    backend.rescan_on_new_rules()
    db.add_hosts((("example.invalid", "malware", "test"),))
    db.bump_generation()
    assert scanner.gate_id() != old_gate
    backend.rescan_on_new_rules()
    assert offered == []
    db.add_hashes((("b" * 64, "test", None),))
    backend.rescan_on_new_rules()
    assert offered == ["C:/ordinary.bin"]
    before_allow = backend._file_rescan_id()
    db.allow_hash("d" * 64)
    assert backend._file_rescan_id() != before_allow
    backend.stop(0)


def test_snapshot_host_and_url_changes_do_not_rescan_but_hashes_do(
    db: Database, scanner: Scanner, tmp_path: Path,
) -> None:
    backend = ProductBackend(db, config.Settings(), scanner)
    baseline = backend._file_rescan_id()
    first = indicators.SnapshotBuilder(tmp_path)
    first.add_hosts((("example.invalid", "malware", "test"),))
    first.add_urls((("https://example.invalid/x", "malware", "test"),))
    indicators.publish(db, first.finish())
    assert backend._file_rescan_id() == baseline
    second = indicators.SnapshotBuilder(tmp_path)
    second.add_hosts((("other.invalid", "malware", "test"),))
    second.add_hashes((("c" * 64, "test", None),))
    indicators.publish(db, second.finish())
    assert backend._file_rescan_id() != baseline
    backend.stop(0)


def test_rule_change_updates_rescan_key(db: Database, scanner: Scanner, marker_rule: Path) -> None:
    backend = ProductBackend(db, config.Settings(), scanner)
    baseline = backend._file_rescan_id()
    marker_rule.write_text('{"rules":[{"id":"test.other","text":["harmless-never-present-marker"]}]}', encoding="utf-8")
    scanner.sigs = SignatureEngine(db)
    assert backend._file_rescan_id() != baseline
    backend.stop(0)


def test_prune_events_keeps_newest_ids_and_other_tables(db: Database) -> None:
    ids = [db.add_event("system", "info", "ordinary", "") for _ in range(5)]
    db.add_quarantine("q1", "C:/ordinary.bin", "a" * 64, 3, {})
    assert db.prune_events(2) == 3
    assert [row["id"] for row in db.events_after(ids[0], 10)] == ids[-2:]
    later = db.add_event("system", "info", "later", "")
    assert later > ids[-1]
    assert [row["id"] for row in db.events_after(ids[-2], 10)] == [ids[-1], later]
    assert db.quarantine_item("q1") is not None


def test_maintenance_prunes_event_log(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    backend = object.__new__(ProductBackend)
    waits = iter((False, True))
    backend._stop = SimpleNamespace(wait=lambda delay: next(waits))
    backend.db = db
    backend.settings = config.Settings()
    backend.rescan_on_new_rules = lambda: None
    calls: list[int] = []
    monkeypatch.setattr(db, "prune_events", lambda: calls.append(1))
    monkeypatch.setattr(backend_module.quarantine, "reconcile", lambda current: None)
    monkeypatch.setattr(backend_module.feeds, "is_due", lambda current, hours: False)
    monkeypatch.setattr(backend_module.feeds, "engine_update_due", lambda current, name, seconds: False)
    backend._maintain()
    assert calls == [1]
