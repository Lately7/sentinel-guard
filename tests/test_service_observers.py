"""A5: the USN journal, process samples, download rescans, and what feeds the queue.

Pure logic against fakes, then the real journal and real processes where this
account may reach them. Records fed to the parser are hostile by assumption.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import time

import pytest

from conftest import MARKER
from sentinel import config
from sentinel.service import usn
from sentinel.service.backend import ProductBackend
from sentinel.service.observers import DbCursorStore, Observers
from sentinel.service.procwatch import (ProcessKey, ProcessWatcher, SnapshotResult, windows_resolve,
                                        windows_snapshot)
from sentinel.service.rescan import DbDownloadStore, Download, MemoryDownloadStore, RescanQueue
from sentinel.service.usn import (FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL, JournalCursor, JournalGap,
                                  UsnRecord, WindowsVolume, parse_batch, parse_journal_data, parse_record,
                                  read_batch, reset_cursor)

windows = pytest.mark.skipif(os.name != "nt", reason="Windows only")
SHA = "a" * 64


def record_v2(*, usn_value: int = 100, reason: int = usn.USN_REASON_CLOSE | usn.USN_REASON_FILE_CREATE,
              name: str = "a.exe", file_ref: int = 7) -> bytes:
    raw = name.encode("utf-16-le")
    length = (60 + len(raw) + 7) & ~7
    head = struct.pack("<IHHQQqqIIIIHH", length, 2, 0, file_ref, 5, usn_value, 0, reason, 0, 0, 0, len(raw), 60)
    return head + raw + b"\0" * (length - 60 - len(raw))


def record_v3(*, name: str = "b.exe") -> bytes:
    raw = name.encode("utf-16-le")
    length = (76 + len(raw) + 7) & ~7
    head = struct.pack("<IHH16s16sqqIIIIHH", length, 3, 0, b"\x07" * 16, b"\x05" * 16, 200, 0,
                       usn.USN_REASON_CLOSE | usn.USN_REASON_DATA_EXTEND, 0, 0, 0, len(raw), 76)
    return head + raw + b"\0" * (length - 76 - len(raw))


def journal(*, journal_id: int = 9, first: int = 0, next_usn: int = 1000, lowest: int = 0) -> bytes:
    return struct.pack("<QQQQQQQ", journal_id, first, next_usn, lowest, 1 << 62, 1 << 25, 1 << 22)


class FakeDevice:
    def __init__(self, query: bytes | Exception = journal(), read: bytes | Exception | None = None) -> None:
        self.query, self.read, self.requests = query, read, []
        self.root = "C:\\"

    def control(self, code: int, data: bytes, output_size: int) -> bytes:
        answer = self.query if code == FSCTL_QUERY_USN_JOURNAL else self.read
        assert code in (FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL)
        if code == FSCTL_READ_USN_JOURNAL:
            self.requests.append(data)
        if isinstance(answer, Exception):
            raise answer
        assert answer is not None
        return answer

    def resolve(self, record: UsnRecord) -> str | None:
        return f"C:\\Users\\u\\{record.name}"


class Store:
    def __init__(self, cursor: JournalCursor | None = None, *, fail: bool = False) -> None:
        self.cursor, self.fail = cursor, fail

    def load(self, volume: str) -> JournalCursor | None:
        if self.fail:
            raise OSError("store")
        return self.cursor

    def save(self, cursor: JournalCursor) -> None:
        if self.fail:
            raise OSError("store")
        self.cursor = cursor


def cursor(next_usn: int = 100, journal_id: int = 9) -> JournalCursor:
    return JournalCursor("C:\\", journal_id, next_usn, 0.0)


def batch(*records: bytes, next_usn: int = 500) -> bytes:
    return struct.pack("<q", next_usn) + b"".join(records)


def test_both_record_versions_parse():
    two = parse_record(record_v2(name="tệp.exe"))
    three = parse_record(record_v3())
    assert two is not None and two.name == "tệp.exe" and two.usn == 100 and len(two.file_ref) == 8
    assert three is not None and three.name == "b.exe" and three.usn == 200 and len(three.file_ref) == 16


@pytest.mark.parametrize("damage", [
    lambda r: r[:30],
    lambda r: struct.pack("<I", 10) + r[4:],
    lambda r: struct.pack("<I", 1 << 30) + r[4:],
    lambda r: r[:4] + struct.pack("<H", 9) + r[6:],
    lambda r: r[:56] + struct.pack("<HH", 5, 60) + r[60:],
    lambda r: r[:56] + struct.pack("<HH", 60000, 60) + r[60:],
    lambda r: r[:56] + struct.pack("<HH", 2, 4) + r[60:],
    lambda r: r[:24] + struct.pack("<q", -1) + r[32:],
    lambda r: r[:60] + b"\x00\xd8\x00\x00" + r[64:],  # a lone surrogate is not a name
])
def test_hostile_records_never_raise(damage):
    assert parse_record(damage(record_v2(name="abcd.exe"))) is None


def test_garbage_batches_are_gaps_not_exceptions():
    assert parse_batch(b"")[2] == JournalGap("malformed_batch")
    assert parse_batch(struct.pack("<q", -5))[2] == JournalGap("malformed_batch")
    assert parse_batch(batch(b"\x01\x02"))[2] == JournalGap("malformed_record")
    assert parse_batch(batch(record_v2(), b"\xff" * 80))[2] == JournalGap("malformed_record")
    for size in range(0, 64):
        parse_batch(os.urandom(size))


def test_impossible_journal_data_is_refused():
    assert parse_journal_data(b"short") is None
    assert parse_journal_data(journal(first=10, next_usn=5)) is None


def test_more_records_than_any_fixed_limit_still_advance():
    # A hard record cap discarded the batch and never moved the cursor: stuck for good.
    device = FakeDevice(read=batch(*[record_v2(usn_value=i + 100) for i in range(6000)], next_usn=900))
    store = Store(cursor())
    result = read_batch("C:\\", device, store, device.resolve)
    assert not result.gaps and len(result.records) == 6000 and store.cursor.next_usn == 900


def test_first_start_is_a_gap_not_a_clean_history():
    device = FakeDevice(read=batch())
    assert read_batch("C:\\", device, Store(), device.resolve).gaps == (JournalGap("no_cursor"),)


@pytest.mark.parametrize(("state", "reason"), [
    (cursor(journal_id=8), "journal_id_changed"),
    (cursor(next_usn=50), "wrapped_cursor"),
    (cursor(next_usn=5000), "wrapped_cursor"),
])
def test_losing_the_thread_demands_reconciliation(state, reason):
    device = FakeDevice(query=journal(lowest=100), read=batch())
    result = read_batch("C:\\", device, Store(state), device.resolve)
    assert result.gaps == (JournalGap(reason),) and result.gaps[0].reconciliation_required


@pytest.mark.parametrize(("code", "reason"), [(5, "access_denied"), (1179, "journal_not_active"),
                                              (1178, "journal_not_active"), (1181, "wrapped_cursor"),
                                              (6, "device_error")])
def test_windows_errors_become_typed_gaps(code, reason):
    failure = OSError(code, "synthetic")
    failure.winerror = code
    device = FakeDevice(query=failure)
    assert read_batch("C:\\", device, Store(cursor()), device.resolve).gaps == (JournalGap(reason),)
    device = FakeDevice(read=failure)
    assert read_batch("C:\\", device, Store(cursor()), device.resolve).gaps == (JournalGap(reason),)


def test_deleted_files_and_metadata_only_changes_are_not_work():
    device = FakeDevice(read=batch(
        record_v2(reason=usn.USN_REASON_CLOSE | usn.USN_REASON_FILE_DELETE | usn.USN_REASON_FILE_CREATE, name="gone.exe"),
        record_v2(reason=usn.USN_REASON_CLOSE, name="touched.exe"),
        record_v2(reason=usn.USN_REASON_CLOSE | usn.USN_REASON_RENAME_NEW_NAME, name="new.exe")))
    result = read_batch("C:\\", device, Store(cursor()), device.resolve)
    assert [c.record.name for c in result.records] == ["new.exe"]


def test_a_file_with_no_path_any_more_is_counted():
    device = FakeDevice(read=batch(record_v2()))
    result = read_batch("C:\\", device, Store(cursor()), lambda record: None)
    assert result.unresolved == 1 and not result.gaps and not result.records


def test_a_cursor_that_cannot_be_saved_is_reported():
    device = FakeDevice(read=batch(record_v2()))
    store = Store(cursor())
    store.save = lambda c: (_ for _ in ()).throw(OSError("disk"))  # type: ignore[method-assign]
    assert read_batch("C:\\", device, store, device.resolve).gaps == (JournalGap("cursor_store_error"),)


def test_read_asks_for_closed_files_only():
    device = FakeDevice(read=batch())
    read_batch("C:\\", device, Store(cursor(next_usn=123)), device.resolve)
    start, mask, only_on_close, _, _, journal_id = struct.unpack("<qIIQQQ", device.requests[0])
    assert (start, mask, only_on_close, journal_id) == (123, 0xFFFFFFFF, 1, 9)


def test_reset_starts_at_the_end_of_the_journal():
    store = Store()
    assert reset_cursor("C:\\", FakeDevice(), store) is None
    assert store.cursor.next_usn == 1000 and store.cursor.journal_id == 9


@windows
def test_real_journal_of_this_volume(tmp_path):
    root = os.path.splitdrive(str(tmp_path))[0] + "\\"
    try:
        volume = WindowsVolume(root)
    except OSError as e:
        pytest.skip(f"no volume handle: {e}")
    store = Store()
    try:
        gap = reset_cursor(root, volume, store)
        if gap is not None:
            pytest.skip(f"journal not available here: {gap.reason}")
        path = tmp_path / "observed.exe"
        path.write_bytes(b"harmless")
        seen: list[str] = []
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not any(p.endswith("observed.exe") for p in seen):
            result = read_batch(root, volume, store, volume.resolve)
            if result.gaps and result.gaps[0].reason == "access_denied":
                pytest.skip("reading the journal needs more rights than this account has")
            assert not result.gaps
            seen += [c.path for c in result.records]
            time.sleep(0.1)
        assert any(os.path.samefile(p, path) for p in seen if p.endswith("observed.exe"))
    finally:
        volume.close()


# -- process samples


def key(pid: int, created: int = 1) -> ProcessKey:
    return ProcessKey(pid, created)


def watcher(snapshot, resolve=lambda k: (f"C:\\p{k.pid}.exe", (1, k.pid)), **options) -> ProcessWatcher:
    return ProcessWatcher(snapshot, resolve, clock=options.pop("clock", time.monotonic), **options)


def test_each_new_process_is_reported_once():
    snapshots = iter([[key(1), key(2)], [key(1), key(2), key(3)]])
    seen = watcher(lambda: next(snapshots))
    assert [t.key.pid for t in seen.poll()] == [1, 2]
    assert [t.key.pid for t in seen.poll()] == [3]


def test_a_reused_pid_is_a_new_process():
    snapshots = iter([[key(1, 100)], [key(1, 200)]])
    seen = watcher(lambda: next(snapshots))
    assert len(seen.poll()) == 1 and len(seen.poll()) == 1


def test_a_full_queue_offers_the_process_again():
    snapshots = iter([[key(1), key(2)], [key(1), key(2)]])
    seen = watcher(lambda: next(snapshots), capacity=1)
    assert [t.key.pid for t in seen.poll()] == [1]
    assert seen.report.queue_saturation == 1
    seen.pop()
    assert [t.key.pid for t in seen.poll()] == [2]


def test_failures_are_counted_once_and_never_grow_without_bound():
    def denied(k: ProcessKey):
        raise PermissionError

    seen = watcher(lambda: SnapshotResult((key(1),), (10, 11)), denied)
    for _ in range(1000):
        seen.poll()
    assert seen.report.inaccessible_images == 3, "two denied by the snapshot, one by its image"
    assert sum(seen.report.gaps.values()) < 10


def test_exit_before_resolution_and_a_failed_snapshot_are_reported():
    def gone(k: ProcessKey):
        raise ProcessLookupError

    seen = watcher(lambda: [key(1)], gone)
    seen.poll()
    assert seen.report.exits_before_resolution == 1

    def broken():
        raise OSError("no snapshot")

    failed = watcher(broken)
    assert failed.poll() == () and failed.report.failed_polls == 1


def test_late_sampling_is_visible():
    now = [0.0]
    seen = watcher(lambda: [], clock=lambda: now[0])
    seen.poll()
    now[0] = 5.0
    seen.poll()
    assert seen.report.largest_gap == 5.0 and seen.report.late_polls == 1


@windows
def test_real_process_is_observed_with_its_image():
    child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(20)"])
    try:
        snapshot = windows_snapshot()
        mine = [k for k in snapshot.keys if k.pid == child.pid]
        assert len(mine) == 1
        path, identity = windows_resolve(mine[0])
        assert os.path.samefile(path, os.path.realpath(sys.executable)) or path.lower().endswith("python.exe")
        assert identity[0] and identity[1]
        with pytest.raises(ProcessLookupError):
            windows_resolve(ProcessKey(child.pid, mine[0].creation_time + 1))
    finally:
        child.kill()
        child.wait()


# -- rescans


def download(file_id: int = 1, *, generation: str = "g1", recorded: float = 100.0, sha: str = SHA) -> Download:
    return Download(1, file_id, f"C:\\d\\{file_id}.exe", sha, generation, recorded)


def test_new_rules_requeue_downloads_judged_by_old_ones():
    queue = RescanQueue(MemoryDownloadStore(), clock=lambda: 100.0)
    queue.remember(download(1, generation="g1"))
    queue.remember(download(2, generation="g2"))
    assert queue.signatures_changed("g2") == 1
    item = queue.pop()
    assert item.path == "C:\\d\\1.exe" and item.reason == "generation_changed" and queue.pop() is None


def test_first_run_fires_once():
    queue = RescanQueue(MemoryDownloadStore(), clock=lambda: 100.0)
    queue.remember(download())
    assert queue.first_run((1, 1)) is True
    assert queue.first_run((1, 1)) is False
    assert queue.first_run((1, 2)) is False


def test_bounds_and_expiry():
    now = [100.0]
    queue = RescanQueue(MemoryDownloadStore(), capacity=1, ttl=50, clock=lambda: now[0])
    assert queue.remember(download(1)) is True
    assert queue.remember(download(2)) is False and queue.gap_counts["store_limit"] == 1
    now[0] = 200.0
    queue.expire()
    assert queue.gap_counts["expired_download"] == 1 and queue.store.values() == ()


def test_changed_content_replaces_the_pending_rescan():
    queue = RescanQueue(MemoryDownloadStore(), clock=lambda: 100.0)
    queue.remember(download(1, generation="old"))
    queue.signatures_changed("new")
    queue.remember(download(1, generation="new", sha="b" * 64))
    assert queue.pop() is None


def test_malformed_downloads_are_refused():
    queue = RescanQueue(MemoryDownloadStore(), clock=lambda: 100.0)
    assert queue.remember(download(sha="not-a-hash")) is False
    assert queue.remember(download(generation="")) is False


def test_download_debt_survives_a_restart(db):
    RescanQueue(DbDownloadStore(db), clock=lambda: 100.0).remember(download(2 ** 100, generation="g1"))
    again = RescanQueue(DbDownloadStore(db), clock=lambda: 100.0)
    assert again.signatures_changed("g2") == 1
    assert again.pop().identity == (1, 2 ** 100)


# -- what reaches the queue


class Backend:
    def __init__(self, room: bool = True) -> None:
        self.room, self.offered = room, []

    def __call__(self, path: str, reason: str, fresh: bool = False) -> bool:
        self.offered.append((path, reason, fresh))
        return self.room


def observers(device: FakeDevice, *, backend: Backend | None = None, db, **options) -> tuple[Observers, Backend]:
    backend = backend or Backend()
    store = DbCursorStore(db)
    store.save(cursor())
    return Observers(backend, [device], store, **options), backend


def test_only_files_that_can_run_are_offered_and_only_once(db):
    device = FakeDevice(read=batch(record_v2(name="run.exe"), record_v2(name="notes.txt"), record_v2(name="run.exe")))
    seen, backend = observers(device, db=db)
    seen.tick_journal()
    assert backend.offered == [("C:\\Users\\u\\run.exe", "journal", False)]


def test_our_own_data_and_system_folders_are_not_offered(db):
    seen, _ = observers(FakeDevice(read=batch()), db=db, data_root="C:\\ProgramData\\SentinelGuard")
    assert not seen.wanted("C:\\ProgramData\\SentinelGuard\\quarantine\\x.exe")
    assert not seen.wanted(os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "x.dll"))
    assert seen.wanted("C:\\Users\\u\\Downloads\\x.exe")


def test_a_gap_reconciles_and_restarts_the_cursor(db):
    calls = []
    device = FakeDevice(query=journal(journal_id=5), read=batch(next_usn=1000))
    seen, _ = observers(device, db=db, reconcile=lambda: calls.append(1))
    seen.tick_journal()
    assert calls == [1]
    assert seen.counts["gap_journal_id_changed"] == 1
    assert DbCursorStore(db).load("C:\\").journal_id == 5
    seen.tick_journal()
    assert calls == [1], "reconciled once, then back to following the journal"


def test_a_burst_past_the_queue_is_counted(db):
    device = FakeDevice(read=batch(record_v2(name="a.exe"), record_v2(name="b.exe")))
    seen, _ = observers(device, db=db, backend=Backend(room=False))
    seen.tick_journal()
    assert seen.counts["queue_full"] == 2


def test_first_run_of_a_download_ignores_the_cache(db):
    queue = RescanQueue(MemoryDownloadStore(), clock=lambda: 100.0)
    queue.remember(download(7))
    watch = watcher(lambda: [key(7)], lambda k: ("C:\\d\\7.exe", (1, 7)))
    seen, backend = observers(FakeDevice(read=batch()), db=db, processes=watch, rescans=queue)
    seen.tick_processes()
    assert backend.offered == [("C:\\d\\7.exe", "process", True)]


def test_status_never_claims_prevention(db):
    seen, _ = observers(FakeDevice(read=batch()), db=db, processes=watcher(lambda: []))
    report = seen.report()
    assert report["prevention"] == "none" and report["process_observation"] == "sampled"


@windows
def test_observed_file_ends_in_quarantine_without_any_client(db, scanner, tmp_path):
    backend = ProductBackend(db, config.Settings(), scanner, file_owner=lambda path: "S-1-5-21-1-1001")
    backend.start()
    try:
        bad = tmp_path / "bad.exe"
        bad.write_bytes(b"head " + MARKER + b" tail")
        assert backend.observe(str(bad), "journal") is True
        deadline = time.monotonic() + 20
        while bad.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not bad.exists()
        assert len(db.quarantine_items()) == 1
    finally:
        backend.stop(2)


def test_new_rules_rescan_downloads(db, scanner, tmp_path, monkeypatch):
    backend = ProductBackend(db, config.Settings(), scanner, file_owner=lambda path: None)
    offered: list[tuple[str, str, bool]] = []
    monkeypatch.setattr(backend, "observe", lambda path, reason, fresh=False: offered.append((path, reason, fresh)) or True)
    generations = iter(["g1", "g2"])
    monkeypatch.setattr(scanner, "gate_id", lambda: next(generations))
    backend.rescans.remember(download(3, generation="g1", recorded=time.time()))
    backend.rescan_on_new_rules()
    assert offered == []
    backend.rescan_on_new_rules()
    assert offered == [("C:\\d\\3.exe", "rescan", True)]
    backend.stop(1)
