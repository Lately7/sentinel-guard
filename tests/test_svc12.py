from __future__ import annotations

import ast
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sentinel.service import burst, shadow
from sentinel.service.etw import ParsedEvent


ROOT = "C:\\Users\\Owner\\Documents"


class Clock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value


def event(kind: str, *, file_object: int = 0, path: str = "", pid: int = 123,
          creation_time: int | None = None) -> ParsedEvent:
    created = (456 if kind == "process_start" else 0) if creation_time is None else creation_time
    return ParsedEvent(kind, pid, 1, file_object, path, creation_time=created)


def test_provisional_burst_logs_counts_without_paths_or_actions() -> None:
    entries: list[dict[str, object]] = []
    clock = Clock()
    observer = shadow.ShadowObserver((ROOT,), writer=entries.append,
                                     image_name=lambda _pid, _created: "C:\\Tools\\Editor.exe",
                                     clock=clock, wall_clock=lambda: 1000.0 + clock.value)
    observer.feed(event("process_start"))
    for index in range(8):
        path = f"{ROOT}\\{'A' if index < 4 else 'B'}\\private-{index}.docx"
        observer.feed(event("name", file_object=index + 1, path=path))
        observer.feed(event("read", file_object=index + 1))
        clock.value += 0.1
        observer.feed(event("write", file_object=index + 1))
    decisions = [item for item in entries if item["kind"] == "decision"]
    alerts = [item for item in decisions if item["reason"] == "provisional_document_burst"]
    assert len(alerts) == 1
    assert alerts[0]["image"] == "Editor.exe"
    assert alerts[0]["documents"] == 8 and alerts[0]["folders"] == 2
    assert alerts[0]["state"] == burst.State.OBSERVE.value
    assert all("private-" not in json.dumps(item) and "path" not in item for item in entries)
    assert observer.report()["would_have_suspended"] == 0
    assert observer.report()["provisional_alerts"] == 1
    source = Path(shadow.__file__).read_text(encoding="utf-8")
    imports = [node for node in ast.walk(ast.parse(source))
               if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert all("repair" not in ast.unparse(node) and "quarantine" not in ast.unparse(node)
               and "suspend" not in ast.unparse(node) for node in imports)


def test_gap_excludes_offline_time_and_resets_partial_burst() -> None:
    entries: list[dict[str, object]] = []
    clock = Clock()
    observer = shadow.ShadowObserver((ROOT,), writer=entries.append, clock=clock,
                                     wall_clock=lambda: 1000.0 + clock.value)
    observer.feed(event("process_start"))
    observer.feed(event("name", file_object=1, path=f"{ROOT}\\A\\one.txt"))
    clock.value += 1
    observer.feed(event("read", file_object=1))
    observer.record_gap()
    clock.value += 86_400
    observer.feed(event("write", file_object=1))
    report = observer.report()
    assert report["first_seen"] == 1100.0
    assert report["events_fed"] == 4
    assert report["days_observed"] == 1 / 86_400
    assert report["gaps"] == 1
    assert report["provisional_alerts"] == 0
    assert any(item.get("reason") == "collector_loss" for item in entries)


def test_missing_join_and_hypotheses_are_visible() -> None:
    entries: list[dict[str, object]] = []
    observer = shadow.ShadowObserver((ROOT,), writer=entries.append)
    observer.feed(event("write", file_object=17))
    report = observer.report()
    assert report["gaps"] == 0
    assert report["unattributed_file"] == 1
    assert report["read_write_events"] == 1
    assert report["usable_read_write_events"] == 0
    assert report["usable_io_share"] == 0.0
    assert report["window_seconds"] == burst.WINDOW_SECONDS
    assert report["burst_documents"] == burst.BURST_DOCUMENTS
    assert report["burst_directories"] == burst.BURST_DIRECTORIES
    assert report["evidence"] == "unconfirmed_etw_requests"
    assert report["would_have_suspended_limit"] == "requires_confirmed_canary_not_supplied_by_etw"


def test_unattributed_events_preserve_partial_burst_and_coverage() -> None:
    observer = shadow.ShadowObserver((ROOT,), writer=lambda _entry: None)
    observer.feed(event("process_start"))
    for index in range(8):
        path = f"{ROOT}\\{'A' if index < 4 else 'B'}\\document-{index}.txt"
        observer.feed(event("name", file_object=index + 1, path=path))
        observer.feed(event("read", file_object=index + 1))
        observer.feed(event("write", file_object=900 + index))
        observer.feed(event("write", file_object=index + 1, pid=3))
        observer.feed(event("write", file_object=index + 1))
    report = observer.report()
    assert report["provisional_alerts"] == 1
    assert report["gaps"] == 0
    assert report["unattributed_file"] == 8
    assert report["unattributed_process"] == 8
    assert report["usable_read_write_events"] == 16
    assert report["read_write_events"] == 32
    assert report["usable_io_share"] == 0.5


def test_unseen_process_scores_then_start_and_stop_replace_identity() -> None:
    image_calls: list[tuple[int, int]] = []
    observer = shadow.ShadowObserver((ROOT,), writer=lambda _entry: None,
                                     image_name=lambda pid, created:
                                     image_calls.append((pid, created)) or "Editor.exe")
    observer.feed(event("name", file_object=1, path=f"{ROOT}\\A\\one.txt"))
    observer.feed(event("read", file_object=1))
    assert observer._processes[123] == (0, "Editor.exe")
    assert image_calls == [(123, 0)]
    assert observer.report()["inferred_processes"] == 1
    assert (123, 0) in observer._scores._history
    observer.feed(event("process_start", creation_time=789))
    assert observer._processes[123] == (789, "Editor.exe")
    assert (123, 0) not in observer._scores._history
    observer.feed(event("read", file_object=1))
    assert (123, 789) in observer._scores._history
    observer.feed(event("process_stop"))
    assert 123 not in observer._processes
    assert (123, 789) not in observer._scores._history
    observer.feed(event("read", file_object=1))
    assert observer._processes[123][0] == 0
    assert observer.report()["inferred_processes"] == 2


def test_capacities_evict_oldest_and_name_ttl_expires(monkeypatch) -> None:
    monkeypatch.setattr(burst, "MAX_FILE_OBJECTS", 2)
    monkeypatch.setattr(burst, "MAX_PROCESSES", 2)
    clock = Clock()
    observer = shadow.ShadowObserver((ROOT,), writer=lambda _entry: None, clock=clock)
    observer.feed(event("process_start", pid=123))
    observer.feed(event("process_start", pid=124))
    observer.feed(event("name", file_object=1, path=f"{ROOT}\\A\\document-0.txt"))
    observer.feed(event("read", file_object=1, pid=124))
    observer.feed(event("process_start", pid=125))
    assert list(observer._processes) == [124, 125]
    assert (124, 456) in observer._scores._history
    for index in range(1, 3):
        observer.feed(event("name", file_object=index + 1,
                            path=f"{ROOT}\\A\\document-{index}.txt"))
    assert list(observer._names) == [2, 3]
    assert (124, 456) in observer._scores._history
    report = observer.report()
    assert report["gaps"] == 0
    assert report["evicted_processes"] == 1
    assert report["evicted_names"] == 1
    clock.value += shadow.NAME_TTL_SECONDS + 1
    observer.feed(event("name", file_object=4, path=f"{ROOT}\\A\\new.txt"))
    assert list(observer._names) == [4]
    assert observer.report()["expired_names"] == 2


def test_non_alert_decisions_do_not_write_a_thousand_lines() -> None:
    entries: list[dict[str, object]] = []
    observer = shadow.ShadowObserver((ROOT,), writer=entries.append)
    observer.feed(event("process_start"))
    observer.feed(event("name", file_object=1, path=f"{ROOT}\\A\\one.txt"))
    for index in range(1000):
        observer.feed(event("read" if index % 2 == 0 else "write", file_object=1))
    assert entries == []
    assert observer.report()["decisions_not_logged"] == 1000


def test_realistic_sparse_joins_still_find_burst() -> None:
    observer = shadow.ShadowObserver((ROOT,), writer=lambda _entry: None)
    observer.feed(event("process_start"))
    for index in range(380):
        observer.feed(event("read", file_object=1000 + index, pid=2000 + index))
    for index in range(10):
        observer.feed(event("name", file_object=index + 1,
                            path=f"{ROOT}\\{'A' if index < 5 else 'B'}\\doc-{index}.txt"))
        observer.feed(event("read", file_object=index + 1))
        observer.feed(event("write", file_object=index + 1))
    report = observer.report()
    assert report["read_write_events"] == 400
    assert report["usable_read_write_events"] == 20
    assert report["usable_io_share"] == 0.05
    assert report["provisional_alerts"] == 1
    assert report["gaps"] == 0


def test_canary_requires_explicit_confirmation_and_attribution() -> None:
    entries: list[dict[str, object]] = []
    observer = shadow.ShadowObserver((ROOT,), writer=entries.append)
    observer.feed(event("process_start"))
    for index in range(2):
        observer.feed(event("name", file_object=index + 1,
                            path=f"{ROOT}\\A\\decoy-{index}.txt"))
        observer.feed(event("write", file_object=index + 1),
                      confirmed_canary=True, strong_attribution=True)
    assert observer.report()["would_have_suspended"] == 1
    assert any(item.get("state") == burst.State.CANDIDATE.value for item in entries)
    assert sum(item.get("would_suspend", False) is True for item in entries) == 1
    assert all("decoy-" not in json.dumps(item) for item in entries)
    unverified = shadow.ShadowObserver((ROOT,), writer=lambda _entry: None)
    unverified.feed(event("process_start"))
    unverified.feed(event("name", file_object=1, path=f"{ROOT}\\A\\decoy.txt"))
    unverified.feed(event("write", file_object=1), confirmed_canary=True)
    assert unverified.report()["would_have_suspended"] == 0
    assert unverified.report()["gaps"] == 1


def test_writer_is_bounded_and_retains_newest_lines(tmp_path: Path) -> None:
    journal = tmp_path / "journal"
    journal.mkdir()
    writer = shadow.RollingDecisionLog(tmp_path, max_bytes=512)
    for index in range(30):
        writer.append({"kind": "decision", "image": "Editor.exe", "sequence": index})
    data = writer.path.read_bytes()
    lines = [json.loads(line) for line in data.splitlines()]
    assert len(data) <= 512
    assert lines[-1]["sequence"] == 29
    assert lines[0]["sequence"] > 0


def test_restart_restores_observation_and_marks_downtime(tmp_path: Path) -> None:
    (tmp_path / "journal").mkdir()
    clock = Clock()
    first = shadow.ShadowObserver(state_root=tmp_path, clock=clock,
                                  wall_clock=lambda: 1000.0 + clock.value)
    first.feed(event("process_start"))
    first.feed(event("read", file_object=999))
    clock.value += 61
    first.feed(event("process_start"))
    original = first.report()
    clock.value += 86_400
    second = shadow.ShadowObserver(state_root=tmp_path, clock=clock,
                                   wall_clock=lambda: 1000.0 + clock.value)
    restored = second.report()
    assert restored["first_seen"] == original["first_seen"]
    assert restored["days_observed"] == original["days_observed"]
    assert restored["events_fed"] == original["events_fed"]
    assert restored["unattributed_file"] == original["unattributed_file"] == 1
    assert restored["read_write_events"] == original["read_write_events"] == 1
    assert restored["gaps"] == original["gaps"] + 1


def test_concurrent_feeds_keep_exact_event_count() -> None:
    observer = shadow.ShadowObserver(writer=lambda _entry: None)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(observer.feed, [event("process_start")] * 100))
    assert observer.report()["events_fed"] == 100
