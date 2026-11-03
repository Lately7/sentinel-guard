"""Regression coverage for journal lookup cost and observer gap reporting."""

from __future__ import annotations

import struct
from collections.abc import Callable

from pytest import MonkeyPatch

from sentinel.service import observers, usn
from sentinel.service.observers import Observers
from sentinel.service.procwatch import ProcessWatcher
from sentinel.service.usn import Batch, JournalCursor, UsnRecord


def _record(name: str, reason: int, file_ref: int) -> bytes:
    encoded = name.encode("utf-16-le")
    length = (60 + len(encoded) + 7) & ~7
    header = struct.pack("<IHHQQqqIIIIHH", length, 2, 0, file_ref, 5, 100, 0,
                         reason | usn.USN_REASON_CLOSE, 0, 0, 0, len(encoded), 60)
    return header + encoded + bytes(length - 60 - len(encoded))


class _Store:
    def __init__(self) -> None:
        self.cursor = JournalCursor("C:\\", 9, 100, 0.0)

    def load(self, volume: str) -> JournalCursor:
        return self.cursor

    def save(self, cursor: JournalCursor) -> None:
        self.cursor = cursor


class _Volume:
    def __init__(self, root: str, records: tuple[bytes, ...] = (), *, end: int = 500) -> None:
        self.root, self.records, self.end = root, records, end
        self.resolved: list[str] = []

    def control(self, code: int, data: bytes, output_size: int) -> bytes:
        if code == usn.FSCTL_QUERY_USN_JOURNAL:
            return struct.pack("<QQQQQQQ", 9, 0, self.end, 0, 1 << 62, 1 << 25, 1 << 22)
        assert code == usn.FSCTL_READ_USN_JOURNAL
        return struct.pack("<q", self.end) + b"".join(self.records)

    def resolve(self, record: UsnRecord) -> str | None:
        self.resolved.append(record.name)
        return None if record.name == "lost.cmd" else self.root + record.name


def _observer(volume: _Volume, store: _Store | None = None) -> Observers:
    return Observers(lambda path, reason, fresh: True, [volume], store or _Store())


def test_name_filter_keeps_new_rename_and_honest_counts() -> None:
    changed = usn.USN_REASON_FILE_CREATE
    volume = _Volume("C:\\", (
        _record("plain.txt", changed, 1),
        _record("old.txt", usn.USN_REASON_RENAME_OLD_NAME, 2),
        _record("new.EXE", usn.USN_REASON_RENAME_NEW_NAME, 2),
        _record("lost.cmd", changed, 3),
    ))
    seen = _observer(volume)
    seen.tick_journal()
    assert volume.resolved == ["new.EXE", "lost.cmd"]
    assert seen.report()["records"] == 1
    assert seen.report()["unresolved"] == 1
    assert seen.report()["skipped_by_name"] == 1


def test_records_key_exists_when_every_change_is_filtered() -> None:
    volume = _Volume("C:\\", (_record("plain.txt", usn.USN_REASON_FILE_CREATE, 1),))
    seen = _observer(volume)
    seen.tick_journal()
    assert volume.resolved == []
    assert seen.report()["records"] == 0
    assert seen.report()["skipped_by_name"] == 1


def test_journal_lag_uses_latest_cursor_for_each_volume(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(observers, "MAX_BATCHES_PER_TICK", 1)
    positions = {"C:\\": [100, 900], "D:\\": [600, None]}

    def read(root: str, *args: object) -> Batch:
        next_usn = positions[root].pop(0)
        if next_usn is None:
            return Batch()
        return Batch(cursor=JournalCursor(root, 9, next_usn, 0.0), journal_end=1000)

    monkeypatch.setattr(observers, "read_batch", read)
    volumes = [_Volume("C:\\"), _Volume("D:\\")]
    seen = Observers(lambda path, reason, fresh: True, volumes, _Store())
    seen.tick_journal()
    assert seen.report()["journal_lag_bytes"] is None
    seen.tick_journal()
    assert seen.report()["journal_lag_bytes"] == 1300
    seen.tick_journal()
    assert seen.report()["journal_lag_bytes"] == 500
    seen.tick_journal()
    assert seen.report()["journal_lag_bytes"] is None


def test_process_gap_excludes_sleep_and_reports_slept_time() -> None:
    now = {"wall": 0.0, "awake": 0.0}
    clock: Callable[[], float] = lambda: now["awake"]
    watcher = ProcessWatcher(lambda: (), lambda key: ("", (0, 0)), clock=clock,
                             wall_clock=lambda: now["wall"], awake_clock=clock)
    watcher.poll()
    now.update(wall=101.0, awake=1.0)
    watcher.poll()
    assert watcher.report.largest_gap == 1.0
    assert watcher.report.slept_seconds == 100.0
    assert watcher.report.late_polls == 0
    now.update(wall=106.0, awake=6.0)
    watcher.poll()
    assert watcher.report.largest_gap == 5.0
    assert watcher.report.slept_seconds == 100.0
    assert watcher.report.late_polls == 1
    seen = Observers(lambda path, reason, fresh: True, [], _Store(), processes=watcher)
    assert seen.report()["largest_gap"] == 5.0
    assert seen.report()["slept_seconds"] == 100.0
