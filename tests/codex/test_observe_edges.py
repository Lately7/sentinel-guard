"""Adversarial but harmless boundaries for service observation."""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.service import burst, observers, reconcile, shadow, usn
from sentinel.service.etw import ParsedEvent


class Cursor:
    def __init__(self, value: str | None = None) -> None:
        self.value = value

    def get(self) -> str | None:
        return self.value

    def set(self, value: str) -> None:
        self.value = value


def _walker(tmp_path: Path, cursor: Cursor, seen: list[str], **bounds: object) -> reconcile.Reconciler:
    drive = tmp_path / "drive"
    drive.mkdir(exist_ok=True)
    data = tmp_path / "home"
    data.mkdir(exist_ok=True)
    return reconcile.Reconciler(lambda path, reason: seen.append(path) or True,
                                cursor.get, cursor.set, data_root=str(data), smart_sources={},
                                drives=[str(drive)], **bounds)


def _event(kind: str, *, pid: int = 100, created: int = 1,
           file_object: int = 0, path: str = "") -> ParsedEvent:
    return ParsedEvent(kind, pid, 1, file_object, path, creation_time=created)


@pytest.mark.parametrize("damage", ["{", '{"v":1', "x" * 100_000,
                                    '{"v":2,"phase":"deep","drive":0,"stack":[]}'])
def test_bad_walk_cursor_starts_over_and_records_loss(tmp_path: Path, damage: str) -> None:
    # A malformed, truncated, huge, or foreign cursor must restart with a visible gap.
    target = tmp_path / "drive" / "safe.exe"
    target.parent.mkdir()
    target.write_bytes(b"harmless")
    seen: list[str] = []
    walker = _walker(tmp_path, Cursor(damage), seen)
    assert walker()
    assert seen == [str(target)]
    assert walker.report()["gaps"]["cursor_lost"] == 1
    assert not walker.report()["complete"]


def test_missing_saved_frame_is_a_gap_not_a_clean_walk(tmp_path: Path) -> None:
    # A vanished resume directory must leave a gap even if the drive itself completes.
    drive = tmp_path / "drive"
    drive.mkdir()
    saved = {"v": 1, "phase": "deep", "smart_cursor": None, "drive": 0,
             "stack": [[str(drive), ""], [str(drive / "gone"), ""]]}
    seen: list[str] = []
    walker = _walker(tmp_path, Cursor(json.dumps(saved)), seen)
    assert walker()
    assert seen == []
    assert walker.report()["gaps"]["source_error"] >= 1
    assert not walker.report()["complete"]


@pytest.mark.parametrize("extended", [False, True])
def test_saved_descendant_cannot_escape_fixed_drive(tmp_path: Path, extended: bool) -> None:
    # A persisted cursor must stay inside its fixed drive because it is only a resume hint.
    drive = tmp_path / "drive"
    drive.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "outside.exe").write_bytes(b"harmless")
    outside_path = "\\\\?\\" + str(outside) if extended else str(outside)
    saved = {"v": 1, "phase": "deep", "smart_cursor": None, "drive": 0,
             "stack": [[str(drive), ""], [outside_path, ""]]}
    seen: list[str] = []
    walker = _walker(tmp_path, Cursor(json.dumps(saved)), seen)
    assert walker()
    assert seen == []
    assert walker.report()["gaps"]["cursor_lost"] == 1


def test_done_cursor_restarts_and_missing_drive_stays_incomplete(tmp_path: Path) -> None:
    # A second debt must walk again, and a lost drive must not produce a complete verdict.
    seen: list[str] = []
    walker = _walker(tmp_path, Cursor(), seen)
    target = tmp_path / "drive" / "safe.exe"
    target.write_bytes(b"harmless")
    assert walker()
    assert walker()
    assert seen == [str(target), str(target)]
    target.unlink()
    (tmp_path / "drive").rmdir()
    assert walker()
    assert walker.report()["gaps"]["source_error"] >= 1
    assert not walker.report()["complete"]


def test_deleted_and_denied_directories_are_visible_gaps(tmp_path: Path,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    # Losing descent through removal or denial must be counted without an exception.
    drive = tmp_path / "drive"
    removed = drive / "removed"
    denied = drive / "denied"
    removed.mkdir(parents=True)
    denied.mkdir()
    real = reconcile.os.scandir

    def scan(path: str):
        if os.fspath(path) == str(removed):
            removed.rmdir()
            raise FileNotFoundError("removed during walk")
        if os.fspath(path) == str(denied):
            raise PermissionError("denied during walk")
        return real(path)

    monkeypatch.setattr(reconcile.os, "scandir", scan)
    walker = _walker(tmp_path, Cursor(), [])
    assert walker()
    assert walker.report()["gaps"]["source_error"] == 1
    assert walker.report()["gaps"]["access_denied"] == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows junctions only")
def test_junction_loop_and_listing_to_descent_swap_are_not_followed(tmp_path: Path,
                                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    # A real junction loop and a directory replaced after listing must never be descended.
    import _winapi

    drive = tmp_path / "drive"
    drive.mkdir()
    loop = drive / "loop"
    try:
        _winapi.CreateJunction(str(drive), str(loop))
    except OSError as exc:
        pytest.skip(f"junction unavailable: {exc}")
    swap = drive / "swap"
    swap.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "outside.exe").write_bytes(b"harmless")
    real = reconcile.os.scandir
    changed = False

    def scan(path: str):
        nonlocal changed
        if os.fspath(path) == str(drive) and not changed:
            changed = True
            # scandir has already enumerated the directory when this iterator is consumed.
            original = real(path)
            entries = list(original)
            original.close()
            swap.rmdir()
            _winapi.CreateJunction(str(outside), str(swap))
            return _Entries(entries)
        return real(path)

    monkeypatch.setattr(reconcile.os, "scandir", scan)
    seen: list[str] = []
    walker = _walker(tmp_path, Cursor(), seen)
    assert walker()
    assert seen == []
    assert walker.report()["gaps"]["reparse_skipped"] >= 2


class _Entries:
    def __init__(self, entries: list[os.DirEntry[str]]) -> None:
        self.entries = entries

    def __enter__(self) -> _Entries:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def __iter__(self):
        return iter(self.entries)


def test_cloud_attribute_is_not_offered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A recall attribute means bytes may not be local, so the candidate must be skipped.
    drive = tmp_path / "drive"
    drive.mkdir()
    target = drive / "cloud.exe"
    target.write_bytes(b"harmless")
    real = reconcile.os.scandir

    class CloudEntry:
        def __init__(self, entry: os.DirEntry[str]) -> None:
            self.entry = entry
            self.name, self.path = entry.name, entry.path

        def stat(self, *, follow_symlinks: bool = False):
            info = self.entry.stat(follow_symlinks=follow_symlinks)
            return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev, st_ino=info.st_ino,
                                   st_file_attributes=reconcile.RECALL_ATTRIBUTES)

    def scan(path: str):
        if os.fspath(path) == str(drive):
            with real(path) as entries:
                return _Entries([CloudEntry(item) for item in entries])
        return real(path)

    monkeypatch.setattr(reconcile.os, "scandir", scan)
    seen: list[str] = []
    walker = _walker(tmp_path, Cursor(), seen)
    assert walker()
    assert seen == []
    assert walker.report()["gaps"]["cloud_placeholder"] == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows extended paths only")
def test_long_and_extended_paths_are_walked(tmp_path: Path) -> None:
    # Extended paths beyond MAX_PATH must still reach risky files without truncation.
    drive = tmp_path / "drive"
    drive.mkdir()
    extended = "\\\\?\\" + str(drive)
    deep = extended
    try:
        for index in range(5):
            deep += "\\" + (str(index) + "a" * 55)
            os.mkdir(deep)
        with open(deep + "\\long.exe", "wb") as stream:
            stream.write(b"harmless")
    except OSError as exc:
        pytest.skip(f"long paths unavailable: {exc}")
    seen: list[str] = []
    data = tmp_path / "data-root"  # tests/conftest.py already uses tmp_path / "home"
    data.mkdir()
    cursor = Cursor()
    walker = reconcile.Reconciler(lambda path, reason: seen.append(path) or True,
                                  cursor.get, cursor.set, data_root=str(data), smart_sources={},
                                  drives=[str(drive)])
    assert walker()
    assert len(seen) == 1 and seen[0].endswith("long.exe")
    assert len(seen[0]) > 260


@pytest.mark.skipif(os.name != "nt", reason="Windows extended names only")
def test_trailing_dot_and_space_do_not_gain_risky_suffix(tmp_path: Path) -> None:
    # Win32 aliases must not turn names ending in a dot or space into executable offers.
    drive = tmp_path / "drive"
    drive.mkdir()
    prefix = "\\\\?\\" + str(drive) + "\\"
    try:
        for name in ("alias.exe.", "alias.exe "):
            with open(prefix + name, "wb") as stream:
                stream.write(b"harmless")
    except OSError as exc:
        pytest.skip(f"extended names unavailable: {exc}")
    if not {"alias.exe.", "alias.exe "}.issubset(set(os.listdir("\\\\?\\" + str(drive)))):
        pytest.skip("filesystem did not preserve trailing characters")
    seen: list[str] = []
    assert _walker(tmp_path, Cursor(), seen)()
    assert seen == []


@pytest.mark.parametrize("damage", [b"{", b'{"version":1,"first_seen":'])
def test_damaged_shadow_checkpoint_is_observation_gap(tmp_path: Path, damage: bytes) -> None:
    # Damaged persisted coverage must be reported as unknown because prior observation is lost.
    journal = tmp_path / "journal"
    journal.mkdir()
    (journal / "shadow-observation.json").write_bytes(damage)
    report = shadow.ShadowObserver(state_root=tmp_path).report()
    assert report["gaps"] >= 1
    decisions = (journal / "shadow-decisions.jsonl").read_text().splitlines()
    assert json.loads(decisions[-1])["reason"] == "checkpoint_invalid"


def test_backward_clock_and_unseen_process_never_confirm_a_burst() -> None:
    # A clock reversal breaks continuity, and inferred identity stays provisional.
    now = [100.0]
    report_log: list[dict[str, object]] = []
    watch = shadow.ShadowObserver((r"C:\Users\u\Documents",), writer=report_log.append,
                                  clock=lambda: now[0], wall_clock=lambda: now[0])
    watch.feed(_event("name", file_object=1, path=r"C:\Users\u\Documents\a.txt"))
    watch.feed(_event("read", file_object=1))
    assert watch.report()["inferred_processes"] == 1
    now[0] = 99.0
    watch.feed(_event("write", file_object=1))
    assert watch.report()["gaps"] == 1
    assert watch.report()["would_have_suspended"] == 0
    assert watch.report()["days_observed"] == 0


def test_pid_reuse_clears_prior_score_and_changes_image() -> None:
    # A new process start with the same pid must discard old evidence and image identity.
    image = {1: "old.exe", 2: "new.exe"}
    watch = shadow.ShadowObserver((r"C:\Users\u\Documents",), writer=lambda _entry: None,
                                  image_name=lambda _pid, created: image[created])
    watch.feed(_event("process_start", created=1))
    watch.feed(_event("name", file_object=1, path=r"C:\Users\u\Documents\a.txt"))
    watch.feed(_event("read", file_object=1))
    assert (100, 1) in watch._scores._history
    watch.feed(_event("process_start", created=2))
    assert (100, 1) not in watch._scores._history
    assert watch._processes[100] == (2, "new.exe")


def test_hundred_thousand_pids_stay_within_capacity() -> None:
    # A long stream of distinct process starts must evict oldest identities at the bound.
    watch = shadow.ShadowObserver(writer=lambda _entry: None)
    for pid in range(10, 100_010):
        watch.feed(_event("process_start", pid=pid))
    assert len(watch._processes) == burst.MAX_PROCESSES
    assert watch.report()["evicted_processes"] == 100_000 - burst.MAX_PROCESSES
    assert 10 not in watch._processes and 100_009 in watch._processes


def test_report_before_file_source_has_unknown_io_coverage() -> None:
    # Before a file event arrives, the report must not call missing IO coverage clean.
    report = shadow.ShadowObserver(writer=lambda _entry: None).report()
    assert report["first_seen"] is None
    assert report["usable_io_share"] is None
    assert report["read_write_events"] == 0


class _Store:
    def __init__(self) -> None:
        self.cursor = usn.JournalCursor("C:\\", 9, 100, 0.0)

    def load(self, volume: str) -> usn.JournalCursor:
        return self.cursor

    def save(self, cursor: usn.JournalCursor) -> None:
        self.cursor = cursor


def _record(name: str, file_ref: int) -> bytes:
    raw = name.encode("utf-16-le")
    length = (60 + len(raw) + 7) & ~7
    header = struct.pack("<IHHQQqqIIIIHH", length, 2, 0, file_ref, 5, 100, 0,
                         usn.USN_REASON_CLOSE | usn.USN_REASON_FILE_CREATE,
                         0, 0, 0, len(raw), 60)
    return header + raw + b"\0" * (length - 60 - len(raw))


def test_journal_name_filter_edges_avoid_unneeded_lookups() -> None:
    # Only exact risky suffixes should incur a file-id lookup before cursor advance.
    names = ("a.EXE", "b.exe.", "c.exe ", "dexe", "e.dll", "f.txt")
    raw = struct.pack("<q", 500) + b"".join(_record(name, index + 1)
                                            for index, name in enumerate(names))
    calls: list[str] = []

    def control(code: int, data: bytes, output_size: int) -> bytes:
        if code == usn.FSCTL_QUERY_USN_JOURNAL:
            return struct.pack("<QQQQQQQ", 9, 0, 1000, 0, 2000, 1000, 100)
        return raw

    result = usn.read_batch("C:\\", SimpleNamespace(control=control), _Store(),
                            lambda record: calls.append(record.name) or "C:\\" + record.name,
                            observers.Observers._wanted_name)
    assert calls == ["a.EXE", "e.dll"]
    assert result.skipped_by_name == 4
    assert result.cursor is not None and result.cursor.next_usn == 500


@pytest.mark.skipif(os.name != "nt", reason="Windows file-id lookup only")
@pytest.mark.parametrize("code", sorted(usn.GONE))
def test_each_gone_code_is_unresolved_without_lookup_error(monkeypatch: pytest.MonkeyPatch,
                                                           code: int) -> None:
    # Every documented gone code means the file vanished, not an actionable lookup failure.
    monkeypatch.setattr(usn, "_k32", SimpleNamespace(OpenFileById=lambda *_args: usn.INVALID_HANDLE))
    monkeypatch.setattr(usn.ctypes, "get_last_error", lambda: code)
    volume = usn.WindowsVolume.__new__(usn.WindowsVolume)
    volume.handle = 1
    record = usn.UsnRecord(2, b"12345678", b"abcdefgh", 100, 1, "gone.exe")
    assert volume.resolve(record) is None


def test_quiet_window_exact_boundary_and_retry_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    # A write is offered at exactly ten seconds, while refused memory stays capped.
    monkeypatch.setattr(observers, "REFUSED_CAP", 2)
    now = [0.0]
    attempts: list[str] = []
    seen = observers.Observers(lambda path, reason, fresh: attempts.append(path) or False,
                               [], SimpleNamespace(), clock=lambda: now[0], reconcile=lambda: False)
    seen._offer(r"C:\d\a.exe", "journal")
    now[0] = observers.RECENT_SECONDS - 0.001
    seen._offer_again()
    assert attempts == []
    now[0] = observers.RECENT_SECONDS
    seen._offer_again()
    assert attempts == [r"C:\d\a.exe"]
    seen._offer(r"C:\d\b.exe", "process")
    seen._offer(r"C:\d\c.exe", "process")
    assert seen.report()["refused_paths"] == 2
    assert seen._owed


def test_journal_lookup_retry_list_exact_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    # The last retry slot is retained, and one more failed lookup creates reconciliation debt.
    monkeypatch.setattr(observers, "LOOKUP_CAP", 2)
    records = tuple(usn.UsnRecord(2, bytes([index]) * 8, b"parent00", index,
                                  usn.USN_REASON_FILE_CREATE, f"{index}.exe")
                    for index in range(3))
    batches = iter((usn.Batch(failed_records=records[:2], lookup_failed=2),
                    usn.Batch(failed_records=records[2:], lookup_failed=1)))
    monkeypatch.setattr(observers, "read_batch", lambda *_args: next(batches, usn.Batch()))
    volume = SimpleNamespace(root="C:\\", resolve=lambda _record: (_ for _ in ()).throw(OSError("denied")))
    seen = observers.Observers(lambda _path, _reason, _fresh: True, [volume],
                               SimpleNamespace(), reconcile=lambda: False, clock=lambda: 0.0)
    seen.tick_journal()
    assert len(seen._lookup_failures) == 2
    assert not seen._owed
    seen.tick_journal()
    assert len(seen._lookup_failures) == 2
    assert seen._owed
