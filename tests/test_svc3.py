"""Observer offers when journal writes settle and retries a saturated lane."""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace

from pytest import MonkeyPatch

from sentinel.db import Database
from sentinel.service import observers as observer_module
from sentinel.service.observers import DbCursorStore, Observers
from sentinel.service.usn import Batch, JournalCursor, ResolvedChange, UsnRecord


def observer(db: Database, submit: Callable[[str, str, bool], bool], now: list[float]) -> Observers:
    return Observers(submit, [], DbCursorStore(db), clock=lambda: now[0], reconcile=lambda: False)


def test_refused_paths_are_retried_with_processes_first_and_reported(db: Database) -> None:
    now = [0.0]
    room = [False]
    attempts: list[tuple[str, str, bool]] = []

    def submit(path: str, reason: str, fresh: bool) -> bool:
        attempts.append((path, reason, fresh))
        return room[0]

    seen = observer(db, submit, now)
    seen._offer("C:\\d\\written.exe", "journal")
    now[0] = 10.0
    seen.tick_journal()
    seen._offer("C:\\d\\running.exe", "process", fresh=True)
    assert seen.report()["refused_paths"] == 2
    room[0] = True
    now[0] = 11.0
    seen.tick_journal()
    assert attempts[-2:] == [
        ("C:\\d\\running.exe", "process", True),
        ("C:\\d\\written.exe", "journal", False),
    ]
    assert seen.report()["refused_paths"] == 0


def test_refused_overflow_remains_owed(db: Database, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(observer_module, "REFUSED_CAP", 1)
    now = [0.0]
    seen = observer(db, lambda path, reason, fresh: False, now)
    seen._offer("C:\\d\\one.exe", "process")
    seen._offer("C:\\d\\two.exe", "process")
    assert seen.report()["refused_paths"] == 1
    assert seen._owed is True


def test_refused_process_displaces_a_journal_path_at_capacity(db: Database, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(observer_module, "REFUSED_CAP", 2)
    now = [0.0]
    room = [False]
    attempts: list[tuple[str, str]] = []

    def submit(path: str, reason: str, fresh: bool) -> bool:
        attempts.append((path, reason))
        return room[0]

    seen = observer(db, submit, now)
    seen._offer("C:\\d\\first.exe", "journal")
    seen._offer("C:\\d\\second.exe", "journal")
    now[0] = 10.0
    seen.tick_journal()
    seen._offer("C:\\d\\running.exe", "process")
    assert seen.report()["refused_paths"] == 2
    room[0] = True
    now[0] = 11.0
    seen.tick_journal()
    assert attempts[-2:] == [("C:\\d\\running.exe", "process"), ("C:\\d\\second.exe", "journal")]
    assert seen._owed is True


def test_new_debt_during_reconciliation_is_preserved(db: Database) -> None:
    now = [0.0]

    def reconcile() -> bool:
        seen._offer("C:\\d\\new.exe", "process")
        return True

    seen = Observers(lambda path, reason, fresh: False, [], DbCursorStore(db),
                     clock=lambda: now[0], reconcile=reconcile)
    seen._offer("C:\\d\\first.exe", "process")
    seen.tick_journal()
    assert seen._owed is True


def test_journal_offer_waits_for_a_full_quiet_window(db: Database) -> None:
    now = [0.0]
    attempts: list[tuple[str, str, bool]] = []
    seen = observer(db, lambda path, reason, fresh: attempts.append((path, reason, fresh)) or True, now)
    seen._offer("C:\\d\\written.exe", "journal")
    now[0] = 9.0
    seen.tick_journal()
    seen._offer("C:\\d\\written.exe", "journal")
    now[0] = 18.9
    seen.tick_journal()
    assert attempts == []
    now[0] = 19.0
    seen.tick_journal()
    assert attempts == [("C:\\d\\written.exe", "journal", False)]


def test_journal_records_enter_the_quiet_window(db: Database, monkeypatch: MonkeyPatch) -> None:
    now = [0.0]
    attempts: list[str] = []
    change = ResolvedChange(UsnRecord(2, b"1", b"2", 1, 1, "written.exe"), "C:\\d\\written.exe")
    batches = iter((Batch(records=(change,)), Batch()))
    monkeypatch.setattr(observer_module, "read_batch", lambda *args: next(batches))
    volume = SimpleNamespace(root="C:\\", resolve=lambda record: change.path)
    seen = Observers(lambda path, reason, fresh: attempts.append(path) or True,
                     [volume], DbCursorStore(db), clock=lambda: now[0])
    monkeypatch.setattr(seen, "wanted", lambda path: True)
    seen.tick_journal()
    assert attempts == []
    now[0] = 10.0
    seen.tick_journal()
    assert attempts == ["C:\\d\\written.exe"]


def test_continuous_journal_writes_are_offered_by_sixty_seconds(db: Database) -> None:
    now = [0.0]
    attempts: list[str] = []
    seen = observer(db, lambda path, reason, fresh: attempts.append(path) or True, now)
    for second in range(0, 61, 5):
        now[0] = float(second)
        seen._offer("C:\\d\\busy.exe", "journal")
        seen.tick_journal()
    assert attempts == ["C:\\d\\busy.exe"]


def test_process_and_fresh_offers_do_not_wait(db: Database) -> None:
    now = [0.0]
    attempts: list[tuple[str, str, bool]] = []
    seen = observer(db, lambda path, reason, fresh: attempts.append((path, reason, fresh)) or True, now)
    seen._offer("C:\\d\\running.exe", "process")
    seen._offer("C:\\d\\fresh.exe", "journal", fresh=True)
    assert attempts == [
        ("C:\\d\\running.exe", "process", False),
        ("C:\\d\\fresh.exe", "journal", True),
    ]


def test_new_write_restarts_quiet_time_for_a_refused_journal_offer(db: Database) -> None:
    now = [0.0]
    room = [False]
    attempts: list[str] = []

    def submit(path: str, reason: str, fresh: bool) -> bool:
        attempts.append(path)
        return room[0]

    seen = observer(db, submit, now)
    seen._offer("C:\\d\\busy.exe", "journal")
    now[0] = 10.0
    seen.tick_journal()
    assert seen.report()["refused_paths"] == 1
    now[0] = 11.0
    room[0] = True
    seen._offer("C:\\d\\busy.exe", "journal")
    seen.tick_journal()
    assert attempts == ["C:\\d\\busy.exe"]
    assert seen.report()["refused_paths"] == 0
    now[0] = 21.0
    seen.tick_journal()
    assert attempts == ["C:\\d\\busy.exe", "C:\\d\\busy.exe"]


def test_refusal_does_not_restart_the_sixty_second_bound(db: Database) -> None:
    now = [0.0]
    room = [False]
    attempts: list[float] = []

    def submit(path: str, reason: str, fresh: bool) -> bool:
        attempts.append(now[0])
        return room[0]

    seen = observer(db, submit, now)
    for second in range(0, 61, 5):
        now[0] = float(second)
        seen._offer("C:\\d\\busy.exe", "journal")
        seen.tick_journal()
    assert seen.report()["refused_paths"] == 1
    now[0] = 65.0
    room[0] = True
    seen._offer("C:\\d\\busy.exe", "journal")
    seen.tick_journal()
    assert attempts[-1] == 65.0


def test_deferred_overflow_is_owed(db: Database, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(observer_module, "RECENT_CAP", 1)
    now = [0.0]
    seen = observer(db, lambda path, reason, fresh: True, now)
    seen._offer("C:\\d\\one.exe", "journal")
    seen._offer("C:\\d\\two.exe", "journal")
    assert seen._owed is True


def test_new_write_cannot_retry_early_when_quiet_map_is_full(db: Database, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(observer_module, "RECENT_CAP", 1)
    now = [0.0]
    room = [False]
    attempts: list[str] = []

    def submit(path: str, reason: str, fresh: bool) -> bool:
        attempts.append(path)
        return room[0]

    seen = observer(db, submit, now)
    seen._offer("C:\\d\\first.exe", "journal")
    now[0] = 10.0
    seen.tick_journal()
    now[0] = 11.0
    seen._offer("C:\\d\\second.exe", "journal")
    seen._offer("C:\\d\\first.exe", "journal")
    assert seen.report()["refused_paths"] == 0
    assert seen._owed is True
    room[0] = True
    seen.tick_journal()
    assert attempts == ["C:\\d\\first.exe"]


def test_new_process_gets_the_free_slot_before_an_old_refusal(db: Database) -> None:
    now = [0.0]
    room = [False]
    attempts: list[str] = []

    def submit(path: str, reason: str, fresh: bool) -> bool:
        attempts.append(path)
        if room[0]:
            room[0] = False
            return True
        return False

    seen = observer(db, submit, now)
    seen._offer("C:\\d\\old.exe", "process")
    targets = iter((SimpleNamespace(path="C:\\d\\new.exe", identity=(1, 2)),))
    seen.processes = SimpleNamespace(poll=lambda: None, pop=lambda: next(targets, None))
    room[0] = True
    seen.tick_processes()
    assert attempts == ["C:\\d\\old.exe", "C:\\d\\new.exe", "C:\\d\\old.exe"]
    assert len(seen._refused) == 1


def test_process_tick_cannot_retry_a_journal_file_before_next_read(db: Database) -> None:
    now = [0.0]
    room = [False]
    attempts: list[float] = []

    def submit(path: str, reason: str, fresh: bool) -> bool:
        attempts.append(now[0])
        return room[0]

    seen = observer(db, submit, now)
    seen._offer("C:\\d\\rewritten.exe", "journal")
    now[0] = 10.0
    seen.tick_journal()
    assert attempts == [10.0]
    seen.processes = SimpleNamespace(poll=lambda: None, pop=lambda: None)
    room[0] = True
    now[0] = 10.2
    seen.tick_processes()
    assert attempts == [10.0]
    now[0] = 15.0
    seen._offer("C:\\d\\rewritten.exe", "journal")
    seen.tick_journal()
    assert attempts == [10.0]
    now[0] = 25.0
    seen.tick_journal()
    assert attempts == [10.0, 25.0]


def test_owe_marks_reconciliation_due(db: Database) -> None:
    seen = observer(db, lambda path, reason, fresh: True, [0.0])
    assert seen.report()["lookup_failed"] == 0
    seen.owe()
    assert seen._owed is True


def test_failed_file_reference_is_retried_on_next_tick(db: Database, monkeypatch: MonkeyPatch) -> None:
    now = [0.0]
    attempts: list[str] = []
    record = UsnRecord(2, b"reference", b"parent", 100, 1, "found.exe")
    batches = iter((Batch(failed_records=(record,), lookup_failed=1, unresolved=1),))
    monkeypatch.setattr(observer_module, "read_batch", lambda *args: next(batches, Batch()))
    volume = SimpleNamespace(root="C:\\", resolve=lambda item: "C:\\d\\found.exe")
    seen = Observers(lambda path, reason, fresh: attempts.append(path) or True,
                     [volume], DbCursorStore(db), clock=lambda: now[0])
    seen.tick_journal()
    assert attempts == [] and seen.report()["lookup_failed"] == 1
    now[0] = 1.0
    seen.tick_journal()
    assert attempts == [] and not seen._lookup_failures
    now[0] = 11.0
    seen.tick_journal()
    assert attempts == ["C:\\d\\found.exe"]


def test_failed_reference_overflow_and_third_failure_owe_reconciliation(
        db: Database, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(observer_module, "LOOKUP_CAP", 1)
    first = UsnRecord(2, b"first", b"parent", 100, 1, "a.exe")
    second = UsnRecord(2, b"second", b"parent", 101, 1, "b.exe")
    batches = iter((Batch(failed_records=(first, second), lookup_failed=2, unresolved=2),))
    monkeypatch.setattr(observer_module, "read_batch", lambda *args: next(batches, Batch()))
    volume = SimpleNamespace(root="C:\\", resolve=lambda item: (_ for _ in ()).throw(OSError("denied")))
    seen = Observers(lambda path, reason, fresh: True, [volume], DbCursorStore(db),
                     reconcile=lambda: False)
    seen.tick_journal()
    assert seen._owed is True and len(seen._lookup_failures) == 1
    seen._owed = False
    seen.tick_journal()
    assert seen.report()["lookup_failed"] == 3 and len(seen._lookup_failures) == 1
    seen.tick_journal()
    assert seen.report()["lookup_failed"] == 4 and not seen._lookup_failures and seen._owed is True


def test_journal_drains_advancing_batches_and_stops_at_limit(db: Database, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(observer_module, "MAX_BATCHES_PER_TICK", 3)
    calls: list[int] = []

    def read(*args: object) -> Batch:
        calls.append(len(calls) + 1)
        return Batch(cursor=JournalCursor("C:\\", 9, calls[-1] * 100, 0.0), journal_end=1000)

    monkeypatch.setattr(observer_module, "read_batch", read)
    volume = SimpleNamespace(root="C:\\", resolve=lambda record: None)
    seen = Observers(lambda path, reason, fresh: True, [volume], DbCursorStore(db))
    seen.tick_journal()
    assert calls == [1, 2, 3]
    monkeypatch.setattr(observer_module, "MAX_BATCHES_PER_TICK", 16)
    seen.tick_journal()
    assert calls == list(range(1, 11))


def test_batch_limit_is_shared_across_volumes(db: Database, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(observer_module, "MAX_BATCHES_PER_TICK", 3)
    calls: list[str] = []

    def read(root: str, *args: object) -> Batch:
        calls.append(root)
        return Batch(cursor=JournalCursor(root, 9, len(calls) * 100, 0.0), journal_end=10000)

    monkeypatch.setattr(observer_module, "read_batch", read)
    volumes = [SimpleNamespace(root=root, resolve=lambda record: None) for root in ("C:\\", "D:\\")]
    seen = Observers(lambda path, reason, fresh: True, volumes, DbCursorStore(db))
    seen.tick_journal()
    assert calls == ["C:\\"] * 3
    seen.tick_journal()
    assert calls == ["C:\\"] * 3 + ["D:\\"] * 3


def test_many_processes_of_one_program_are_one_offer(db: Database) -> None:
    now = [0.0]
    offered: list[tuple[str, str, bool]] = []

    def submit(path: str, reason: str, fresh: bool) -> bool:
        offered.append((path, reason, fresh))
        return True

    seen = Observers(submit, [], DbCursorStore(db), clock=lambda: now[0])
    for _ in range(20):
        seen._offer("C:\\Users\\u\\app.exe", "process")
    assert len(offered) == 1
    seen._offer("C:\\Users\\u\\app.exe", "process", fresh=True)
    assert len(offered) == 2, "a first run is never held back"
    now[0] = 10.0
    seen._offer("C:\\Users\\u\\app.exe", "process")
    assert len(offered) == 3
