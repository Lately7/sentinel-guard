"""Real-time protection: honest "on" state (RT-026), both registry views (RT-027),
locked-file retry (RT-016), bounded pending state (RT-017), stop barrier (RT-018)."""

from __future__ import annotations

import pytest

import threading

from conftest import MARKER
from sentinel import config, watcher
from sentinel.engine.verdict import Verdict
from sentinel.watcher import RUN_KEYS, NothingToWatch, RealtimeProtection, ScanQueue, read_run_entries


def test_nothing_to_watch_is_an_error_not_running(db, scanner, tmp_path):
    s = config.Settings(watch_dirs=[str(tmp_path / "does-not-exist")], use_defender=False)
    rt = RealtimeProtection(db, s, scanner)
    with pytest.raises(NothingToWatch):
        rt.start()
    assert not rt.running


def test_existing_folder_starts(db, scanner, tmp_path):
    s = config.Settings(watch_dirs=[str(tmp_path)], use_defender=False)
    rt = RealtimeProtection(db, s, scanner)
    rt.start()
    try:
        assert rt.running and rt.files.dirs == [str(tmp_path)]
    finally:
        rt.stop()


class FakeReg:
    """Just enough of winreg: per (hive, view) value lists."""

    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE = 1, 2
    KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 0x20019, 0x0100, 0x0200

    def __init__(self, data):
        self.data = data
        self.opened = []

    def OpenKey(self, hive, key, reserved, access):
        view = access & (self.KEY_WOW64_64KEY | self.KEY_WOW64_32KEY)
        self.opened.append((hive, view))
        values = self.data.get((hive, view, key))
        if values is None:
            raise OSError("no such key")
        reg = self

        class Key:
            def __enter__(self):
                return values

            def __exit__(self, *a):
                return False
        reg._values = values
        return Key()

    def EnumValue(self, key, i):
        if i >= len(key):
            raise OSError("no more")
        name, value = key[i]
        return name, value, 1


def test_run_keys_are_read_from_both_hklm_views():
    r = FakeReg
    run = RUN_KEYS[0]
    reg = FakeReg({
        (r.HKEY_CURRENT_USER, 0, run): [("Chat", r"C:\Users\u\chat.exe")],
        (r.HKEY_LOCAL_MACHINE, r.KEY_WOW64_64KEY, run): [("Driver", r"C:\Program Files\drv.exe")],
        (r.HKEY_LOCAL_MACHINE, r.KEY_WOW64_32KEY, run): [("Updater", r"C:\Program Files (x86)\upd.exe")],
    })
    entries = read_run_entries(reg)
    assert entries == {
        f"HKCU\\{run}\\Chat": r"C:\Users\u\chat.exe",
        f"HKLM\\{run}\\Driver": r"C:\Program Files\drv.exe",
        f"HKLM32\\{run}\\Updater": r"C:\Program Files (x86)\upd.exe",
    }
    assert (r.HKEY_LOCAL_MACHINE, r.KEY_WOW64_32KEY) in reg.opened


# ------------------------------------------------- scan queue (RT-016..018)

class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class FlakyScanner:
    """Answers "unreadable" (a locked file) for the first `locked` scans."""

    def __init__(self, real, locked: int, during_scan=None) -> None:
        self.real, self.locked, self.during_scan, self.calls = real, locked, during_scan, 0

    def scan_file(self, path, *, use_cache=True):
        self.calls += 1
        if self.during_scan:
            self.during_scan()
        if self.calls <= self.locked:
            return Verdict(name="bad.bin", sha256="", size=0, path=str(path),
                           skipped="unreadable: The process cannot access the file because it is being used by another process")
        return self.real.scan_file(path, use_cache=use_cache)


@pytest.fixture
def queue_parts(db, scanner, tmp_path, monkeypatch):
    monkeypatch.setattr(watcher, "SIZE_RECHECK_SECONDS", 0)
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"head " + MARKER + b" tail")
    return db, scanner, bad, config.Settings(watch_dirs=[str(tmp_path)], use_defender=False)


def drain(q: ScanQueue, clock: Clock, step: float = 0.5, until: float = 120.0) -> None:
    end = clock.t + until
    while clock.t < end:
        for item in q._due():
            q._scan_one(*item)
        if not q._pending:
            return
        clock.t += step


def test_locked_file_is_retried_until_it_can_be_read(queue_parts):
    db, scanner, bad, settings = queue_parts
    clock = Clock()
    flaky = FlakyScanner(scanner, locked=2)
    q = ScanQueue(flaky, db, settings, clock=clock)
    q.submit(str(bad))
    drain(q, clock)
    assert flaky.calls == 3
    assert not bad.exists(), "the marker file is quarantined once the lock is gone"


def test_locked_file_gives_up_after_bounded_attempts_and_says_so(queue_parts):
    db, scanner, bad, settings = queue_parts
    clock = Clock()
    flaky = FlakyScanner(scanner, locked=10**6)
    q = ScanQueue(flaky, db, settings, clock=clock)
    q.submit(str(bad))
    drain(q, clock, until=600)
    assert flaky.calls == len(watcher.RETRY_DELAYS) + 1
    assert not q._pending
    titles = [e["title"] for e in db.events(source="watcher")]
    assert "Chưa quét được tệp" in titles, "an unscanned file is never silently treated as clean"


def test_pending_paths_are_bounded_and_overflow_is_reported(queue_parts, monkeypatch, tmp_path):
    db, scanner, _bad, settings = queue_parts
    monkeypatch.setattr(watcher, "MAX_PENDING", 5)
    q = ScanQueue(scanner, db, settings, clock=Clock())
    for i in range(8):
        q.submit(str(tmp_path / f"f{i}.txt"))
    assert len(q._pending) == 5
    assert q.dropped == 3
    q._report_overflow()
    assert any(e["title"] == "Quá nhiều tệp thay đổi cùng lúc" for e in db.events(source="watcher"))


def test_a_constantly_changing_file_is_still_scanned(queue_parts):
    db, scanner, bad, settings = queue_parts
    clock = Clock()
    q = ScanQueue(scanner, db, settings, clock=clock)
    start = clock.t
    seen = []
    while clock.t - start < 120 and not seen:
        q.submit(str(bad))  # a new event every second keeps resetting the quiet timer
        seen = q._due()
        clock.t += 1.0
    assert seen, "debouncing must not postpone a busy file forever"
    assert clock.t - start <= watcher.MAX_AGE_SECONDS + 2


def test_stop_during_a_scan_blocks_the_automatic_quarantine(queue_parts):
    db, scanner, bad, settings = queue_parts
    q = ScanQueue(FlakyScanner(scanner, locked=0, during_scan=lambda: q.stop()), db, settings, clock=Clock())
    q._scan_one(str(bad), 0)
    assert bad.exists(), "a protection run that was switched off must not quarantine"
    assert any(e["title"] == "Phát hiện mối đe dọa" for e in db.events(source="watcher")), "the finding is still recorded"
    q.submit(str(bad))
    assert not q._pending, "no new work after stop"


def test_stop_waits_for_an_action_in_progress(queue_parts):
    db, scanner, _bad, settings = queue_parts
    q = ScanQueue(scanner, db, settings)
    held, release = threading.Event(), threading.Event()

    def acting():
        with q.barrier.action():
            held.set()
            release.wait(5)

    t = threading.Thread(target=acting)
    t.start()
    held.wait(5)
    try:
        assert q.stop(timeout=0.2) is False, "stop reports that an action is still finishing"
    finally:
        release.set()
        t.join()
    assert q.stop(timeout=1) is True


def test_realtime_stop_reports_a_closed_barrier(db, scanner, tmp_path):
    rt = RealtimeProtection(db, config.Settings(watch_dirs=[str(tmp_path)], use_defender=False), scanner)
    rt.start()
    assert rt.stop() is True
    assert not rt.running
