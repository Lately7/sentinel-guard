"""Regression checks for feed retries, rule trials, and YARA coverage."""

from __future__ import annotations

import hashlib
import io
import os
import time
import zipfile
from pathlib import Path

import pytest

from sentinel import feeds, yarafeed
from sentinel.gate_v2.content import BoundReader
from sentinel.gate_v2.contract import (Coverage, EngineResult, FileIdentity, ScanRequest,
                                       StageStatus, VerdictCode)
from sentinel.gate_v2 import rules as rule_module
from sentinel.gate_v2.rules import YaraXAdapter
from sentinel.service.workerclient import WorkerFailure, WorkerSession


def test_offline_feed_pass_preserves_snapshot_and_retries_hourly(db, monkeypatch):
    feed = feeds.Feed("sample", "unused", "bad_hosts", "malware", feeds.parse_hosts)
    now = 1_000_000.0
    monkeypatch.setattr(feeds.time, "time", lambda: now)
    feeds._update_all(db, [feed], lambda _: "unsafe.example", lambda _: b"", False)
    old_pointer = db.get_meta("indicators_file")
    old_generation = db.generation()
    now += 7 * 3600

    def offline(_url: str) -> str:
        raise OSError("offline")

    result = feeds._update_all(db, [feed], offline, lambda _: b"", False)
    assert result["sample"].startswith("error:")
    assert db.get_meta("indicators_file") == old_pointer
    assert db.generation() == old_generation
    assert db.indicators.rows_for_source("hosts", "sample") == [("unsafe.example", "malware", "sample")]
    assert not feeds.is_due(db, 6, now=now + 60)
    assert feeds.is_due(db, 6, now=now + feeds.ENGINE_RETRY_AFTER + 1)


def test_partial_feed_success_still_publishes(db, monkeypatch):
    monkeypatch.setattr(feeds.time, "time", lambda: 1_000_000.0)
    good = feeds.Feed("good", "good", "bad_hosts", "malware", feeds.parse_hosts)
    bad = feeds.Feed("bad", "bad", "bad_hosts", "malware", feeds.parse_hosts)

    def fetch(url: str) -> str:
        if url == "bad":
            raise OSError("offline")
        return "unsafe.example"

    before = db.generation()
    result = feeds._update_all(db, [good, bad], fetch, lambda _: b"", False)
    assert result["good"].startswith("ok") and result["bad"].startswith("error:")
    assert db.generation() > before


def _package(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("core.yar", source)
    return buf.getvalue()


def test_rule_update_trials_all_sources_and_keeps_old_file_on_worker_failure(
        sentinel_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    bundled = tmp_path / "rules"
    bundled.mkdir()
    (bundled / "bundled.yar").write_text("rule bundled { condition: false }", encoding="utf-8")
    monkeypatch.setattr(yarafeed, "__file__", str(tmp_path / "yarafeed.py"))
    user = sentinel_home / "rules"
    user.mkdir(exist_ok=True)
    (user / "other.yar").write_text("rule other { condition: false }", encoding="utf-8")
    (user / "patterns.json").write_text('{"rules":[]}', encoding="utf-8")
    dest = user / yarafeed.TARGET
    dest.write_text("rule old { condition: false }", encoding="utf-8")
    candidate = "rule new { condition: false }"
    monkeypatch.setattr(yarafeed.importlib.util, "find_spec", lambda _: object())
    monkeypatch.setattr(yarafeed, "compile_filtered", lambda _: (candidate, 1, 0))
    sessions = []
    fail = [True]

    class Session:
        def __init__(self, *, json_packs, yara_sources):
            self.json_packs = json_packs
            self.yara_sources = yara_sources
            self.closed = False
            sessions.append(self)

        def call(self, op, args, *, deadline_ns):
            assert op == "scan" and args["engine"] == "yara_x"
            assert deadline_ns > time.monotonic_ns()
            if fail[0]:
                raise RuntimeError("worker exited under memory cap")
            identity = FileIdentity.from_dict(args["identity"])
            return {"engine_result": EngineResult(
                2, "yara_x", args["request"]["file_id"], identity,
                StageStatus.COMPLETED, VerdictCode.CLEAN,
                Coverage(0, (), "full", 0, 0, 0, 0, (), (), (), "verified"),
                (), None, None, "trial", "READY", time.monotonic_ns(), 0, None).to_dict()}

        def close(self):
            self.closed = True

    result = yarafeed.update(fetch=lambda _: _package(candidate), session_factory=Session)
    assert result.startswith("error:")
    assert dest.read_text(encoding="utf-8") == "rule old { condition: false }"
    assert sessions[0].closed
    assert {name for _, name, _ in sessions[0].yara_sources} == {
        str(bundled / "bundled.yar"), str(user / "other.yar"), str(dest)}
    assert next(src for _, name, src in sessions[0].yara_sources if name == str(dest)) == candidate
    assert str(user / "patterns.json") in {name for name, _, _ in sessions[0].json_packs}
    fail[0] = False
    assert yarafeed.update(fetch=lambda _: _package(candidate), session_factory=Session) == "ok: 1 rules"
    assert sessions[1].closed
    assert dest.read_text(encoding="utf-8") == candidate


def test_a_file_past_the_resident_limit_stays_partial_even_when_head_and_tail_meet(monkeypatch):
    # Head and tail are scanned as two buffers, so no rule sees across the seam:
    # every byte was read, and calling that complete would be a false clean.
    monkeypatch.setattr(rule_module, "TAIL_BYTES", 8)
    size = 72
    data = b"A" * size
    identity = FileIdentity(None, None, None, size, hashlib.sha256(data).hexdigest(), None, None)
    reader = BoundReader.from_bytes(data, identity, resident_limit=64)
    request = ScanRequest(2, "coverage", "coverage", None, data, "test", "memory",
                          "evidence-v1", "evidence-v1", time.monotonic_ns() + 1_000_000_000,
                          None, False)

    class Scanner:
        def scan(self, payload):
            return type("Matches", (), {"matching_rules": ()})()

    adapter = object.__new__(YaraXAdapter)
    adapter._rules = object()
    adapter._yara = type("Yara", (), {"TimeoutError": TimeoutError})
    adapter.manifest = ()
    adapter.ruleset_digest = "test"
    monkeypatch.setattr(YaraXAdapter, "_scanner", lambda self: Scanner())
    result = adapter.scan_bound(request, identity, type("Token", (), {"cancelled": lambda self: False})(), reader)
    assert result.status is StageStatus.PARTIAL and result.verdict is VerdictCode.UNKNOWN


def _rules_home(sentinel_home: Path) -> Path:
    user = sentinel_home / "rules"
    user.mkdir(exist_ok=True)
    return user / yarafeed.TARGET


@pytest.mark.skipif(os.name != "nt", reason="restricted workers need Windows")
def test_the_trial_passes_through_a_real_worker(sentinel_home):
    yarafeed._trial_worker("rule fine { condition: false }", _rules_home(sentinel_home), WorkerSession)


@pytest.mark.skipif(os.name != "nt", reason="restricted workers need Windows")
def test_a_rule_set_the_worker_cannot_hold_fails_the_trial(sentinel_home):
    with pytest.raises(WorkerFailure):
        yarafeed._trial_worker("rule fine { condition: false }", _rules_home(sentinel_home),
                               lambda **k: WorkerSession(memory_limit=8 * 1024 * 1024, **k))


def test_outside_the_service_no_worker_is_started_for_a_rule_update(sentinel_home, monkeypatch):
    monkeypatch.setattr(yarafeed.importlib.util, "find_spec", lambda _: object())
    monkeypatch.setattr(yarafeed, "compile_filtered", lambda _: ("rule new { condition: false }", 1, 0))
    monkeypatch.setattr(yarafeed, "_trial_worker", lambda *a: pytest.fail("portable scans have no worker"))
    assert yarafeed.update(fetch=lambda _: _package("rule new { condition: false }")) == "ok: 1 rules"
