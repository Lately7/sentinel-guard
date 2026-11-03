"""Coverage and safety checks for the disposable false-positive sampler."""

from __future__ import annotations

import json

import pytest
import os
import hashlib
from contextlib import contextmanager
from pathlib import Path

from tools import fp_sample


def test_sample_uses_product_gate_without_quarantine(db, marker_rule: Path, sentinel_home: Path, tmp_path: Path,
                                                     monkeypatch) -> None:
    from sentinel.engine.scanner import Scanner
    from sentinel.gate_v2 import orchestrator
    from sentinel.gate_v2.contract import ActionCode, VerdictCode
    from conftest import MARKER

    candidate = tmp_path / "legitimate.txt"
    candidate.write_bytes(b"ordinary data " + MARKER)
    (sentinel_home / "settings.json").write_text('{"auto_quarantine": true}', encoding="utf-8")
    called: list[bool] = []
    real_scan = orchestrator.scan

    def record(*args, **kwargs):
        called.append(kwargs["auto_quarantine"])
        return real_scan(*args, **kwargs)

    monkeypatch.setattr(orchestrator, "scan", record)
    decision = fp_sample._scan(Scanner(db, use_defender=False, use_clamav=False),
                               str(candidate), ("core", "json_rules"))
    assert called == [False]
    assert decision.verdict is VerdictCode.MALICIOUS
    assert decision.action_decision.action is not ActionCode.QUARANTINE
    assert candidate.read_bytes() == b"ordinary data " + MARKER


def test_main_uses_disposable_home_and_restores_environment(tmp_path: Path, monkeypatch,
                                                           capsys) -> None:
    from sentinel import db as db_module
    from sentinel.engine import scanner as scanner_module

    home = tmp_path / "sample-home"
    home.mkdir()
    old_home = os.environ.get("SENTINEL_HOME")
    old_port = os.environ.get("SENTINEL_CLAMD_PORT")

    @contextmanager
    def temporary(**kwargs):
        yield str(home)

    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def bind(self, address):
            assert address[0] == "127.0.0.1" and address[1] == 0

        def getsockname(self):
            return "127.0.0.1", 45678

    class Db:
        def close(self):
            pass

    lifecycle: list[str] = []

    class Clam:
        def start(self):
            lifecycle.append("start")

        def stop(self):
            lifecycle.append("stop")

    class Scanner:
        clamav = Clam()

        def __init__(self, db, **kwargs):
            assert os.environ["SENTINEL_HOME"] == str(home)
            assert os.environ["SENTINEL_CLAMD_PORT"] == "45678"
            assert kwargs == {"use_defender": False, "use_clamav": True}

    monkeypatch.setattr(fp_sample.tempfile, "TemporaryDirectory", temporary)
    monkeypatch.setattr(fp_sample.socket, "socket", Socket)
    monkeypatch.setattr(db_module, "Database", Db)
    monkeypatch.setattr(scanner_module, "Scanner", Scanner)
    monkeypatch.setattr(fp_sample, "_report", lambda *args: {"sample": "temporary"})
    assert fp_sample.main(["1", str(tmp_path), "--engines", "core,clamav"]) == 0
    assert json.loads(capsys.readouterr().out) == {"sample": "temporary"}
    assert lifecycle == ["start", "stop"]
    assert os.environ.get("SENTINEL_HOME") == old_home
    assert os.environ.get("SENTINEL_CLAMD_PORT") == old_port


def test_copied_rules_load_and_source_is_unchanged(tmp_path: Path, monkeypatch) -> None:
    from sentinel.db import Database
    from sentinel.engine.scanner import Scanner
    from sentinel.gate_v2.contract import VerdictCode
    from conftest import MARKER

    source = tmp_path / "downloaded"
    rules = source / "rules"
    rules.mkdir(parents=True)
    pack = rules / "test.json"
    original = json.dumps({"rules": [{"id": "test.marker", "severity": "critical",
                                      "text": [MARKER.decode()]}]}).encode()
    pack.write_bytes(original)
    home = tmp_path / "sample-home"
    home.mkdir()
    assert fp_sample._stage_rules(source, home) is None
    monkeypatch.setenv("SENTINEL_HOME", str(home))
    db = Database()
    try:
        candidate = tmp_path / "application.txt"
        candidate.write_bytes(MARKER)
        decision = fp_sample._scan(Scanner(db, use_defender=False, use_clamav=False),
                                   str(candidate), ("core", "json_rules"))
        assert decision.verdict is VerdictCode.MALICIOUS
        assert any(result.engine_id == "json_rules" and result.evidence
                   for result in decision.engine_results)
    finally:
        db.close()
    assert pack.read_bytes() == original


def test_report_counts_unreadable_and_shows_partial_engine_coverage(
        db, marker_rule: Path, tmp_path: Path, monkeypatch) -> None:
    from sentinel.engine.scanner import Scanner
    from conftest import MARKER

    clean = tmp_path / "clean.txt"
    clean.write_bytes(b"ordinary")
    flagged = tmp_path / "flagged.exe"
    flagged.write_bytes(MARKER)
    missing = tmp_path / "missing.bin"
    paths = [str(clean), str(flagged), str(missing)]
    monkeypatch.setattr(fp_sample, "walk", lambda roots, limit, seed: iter(paths))
    report = fp_sample._report(Scanner(db, use_defender=False, use_clamav=False),
                               [str(tmp_path)], 3, 17, fp_sample.ENGINES)
    assert report["files_sampled"] == 3
    assert report["by_file_type"] == {".txt": 1, ".exe": 1, ".bin": 1}
    assert report["verdict_counts"] == {"malicious": 1, "unknown": 2}
    assert report["rate"]["checked"] == 1
    assert report["rate"]["false_positives"] == 1
    assert report["rate"]["upper_95"] == pytest.approx(1)
    assert report["scope"].startswith("Tỷ lệ chưa đầy đủ:")
    assert not report["engine_coverage"]["clamav"]["ran"]
    assert report["engine_coverage"]["clamav"]["statuses"]["not_run"] == 3
    assert any(item["path"] == str(missing) and item["verdict"] == "unknown"
               for item in report["findings"])
    flagged_detail = next(item["details"] for item in report["findings"]
                          if item["path"] == str(flagged))
    assert {"engine": "json_rules", "rule": "test.marker"} in flagged_detail
    assert MARKER.decode() not in json.dumps(report)


def test_seeded_walk_and_zero_hit_bound(tmp_path: Path) -> None:
    for index in range(20):
        (tmp_path / f"{index:02}.txt").write_bytes(b"ordinary")
    first = list(fp_sample.walk([str(tmp_path)], 7, 123))
    assert first == list(fp_sample.walk([str(tmp_path)], 7, 123))
    assert first != list(fp_sample.walk([str(tmp_path)], 7, 456))
    assert fp_sample._upper_bound(0, 6000) == 3 / 6000
    assert fp_sample._upper_bound(0, 0) is None
    assert fp_sample._upper_bound(1, 10) > 0.1


def test_installed_state_paths_are_rejected(tmp_path: Path, monkeypatch) -> None:
    program_data = tmp_path / "ProgramData"
    monkeypatch.setenv("ProgramData", str(program_data))
    assert fp_sample._protected(program_data / "SentinelGuard" / "rules")
    assert not fp_sample._protected(tmp_path / "ordinary")


def test_snapshot_copy_and_generation_are_reported(tmp_path: Path, monkeypatch) -> None:
    from sentinel import indicators
    from sentinel.db import Database
    from sentinel.engine.scanner import Scanner

    source = tmp_path / "copy"
    snapshots = source / "indicators"
    snapshots.mkdir(parents=True)
    original = indicators.SnapshotBuilder(snapshots).finish()
    home = tmp_path / "sample-home"
    home.mkdir()
    staged = fp_sample._stage_rules(source, home)
    assert staged is not None and staged.read_bytes() == original.read_bytes()

    monkeypatch.setenv("SENTINEL_HOME", str(home))
    db = Database()
    try:
        db.set_meta(indicators.POINTER_KEY, str(staged))
        db.bump_generation()
        report = fp_sample._report(Scanner(db, use_defender=False, use_clamav=False),
                                   [], 1, 0, ("core",))
    finally:
        db.close()
    assert report["snapshot_generation"] == hashlib.sha256(original.read_bytes()).hexdigest()
    assert report["db_generation"] == 1
    assert len(report["configured_rule_generations"]["json_rules"]) == 64
