"""What puts work in the service's queue by itself (A5): the USN journal and process samples.

These find files after they appeared, not before they run: without a driver
nothing here can stop a program from starting. status() says so, and every way
of losing track of changes is counted and followed by a reconciliation scan.
"""

from __future__ import annotations

import json
import logging
import ntpath
import threading
import time
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from ..db import Database
from ..gate_v2 import winfile
from .procwatch import ProcessWatcher
from .rescan import RescanQueue
from .usn import Device, JournalCursor, UsnRecord, read_batch, reset_cursor

log = logging.getLogger(__name__)

JOURNAL_SECONDS = 5.0
RECONCILE_SECONDS = 3600.0  # a whole-machine scan: a journal that keeps failing must not repeat it
RECENT_SECONDS = 10.0
RECENT_CAP = 4096
MAX_QUIET_SECONDS = 60.0
REFUSED_CAP = 4096
LOOKUP_CAP = 4096
MAX_BATCHES_PER_TICK = 16
# Files that can run, or carry something that can. Everything else changes all
# day (browser caches, logs) and cannot start by being opened.
RISKY_SUFFIXES = frozenset((
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi", ".msp", ".appx", ".msix",
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar",
    ".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".vhdx", ".cab",
    ".docm", ".xlsm", ".pptm", ".one",
))


class Volume(Device, Protocol):
    root: str

    def resolve(self, record: UsnRecord) -> str | None: ...


@dataclass(frozen=True)
class _Deferred:
    path: str
    first: float
    last: float


@dataclass(frozen=True)
class _Refused:
    path: str
    reason: str
    fresh: bool
    first: float | None = None


class DbCursorStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    def load(self, volume: str) -> JournalCursor | None:
        raw = self.db.get_meta(f"usn:{volume}", "")
        if not raw:
            return None
        try:
            item = json.loads(raw)
            return JournalCursor(volume, int(item["id"]), int(item["next"]), float(item["at"]))
        except (ValueError, KeyError, TypeError) as e:
            raise OSError("damaged cursor") from e

    def save(self, cursor: JournalCursor) -> None:
        self.db.set_meta(f"usn:{cursor.volume}",
                         json.dumps({"id": cursor.journal_id, "next": cursor.next_usn, "at": cursor.checkpoint}))


class Observers:
    def __init__(self, submit: Callable[[str, str, bool], bool], volumes: Iterable[Volume], store: DbCursorStore,
                 *, processes: ProcessWatcher | None = None, rescans: RescanQueue | None = None,
                 reconcile: Callable[[], bool | None] = lambda: True, data_root: str = "",
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.submit = submit
        self.volumes = list(volumes)
        self.store = store
        self.processes = processes
        self.rescans = rescans
        self.reconcile = reconcile
        self.data_root = ntpath.normcase(data_root)
        self.clock = clock
        self.counts: Counter[str] = Counter()
        self._recent: OrderedDict[str, float] = OrderedDict()
        self._again: OrderedDict[str, _Deferred] = OrderedDict()
        self._refused: OrderedDict[str, _Refused] = OrderedDict()
        self._lookup_failures: OrderedDict[tuple[str, bytes], tuple[Volume, UsnRecord, int]] = OrderedDict()
        self._next_volume = 0
        self._lock = threading.RLock()
        self._owed = False  # something was missed and a reconciliation has to make up for it
        self._debt_version = 0
        self._gap_of: dict[str, str] = {}
        self._reconciled_at = float("-inf")
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def wanted(self, path: str) -> bool:
        lowered = ntpath.normcase(path)
        if ntpath.splitext(lowered)[1] not in RISKY_SUFFIXES:
            return False
        if self.data_root and lowered.startswith(self.data_root + "\\"):
            return False
        return not winfile.is_protected(path)  # nothing there may be acted on, and updates churn it

    def _offer(self, path: str, reason: str, *, fresh: bool = False) -> None:
        with self._lock:
            key = ntpath.normcase(path)
            if reason == "journal" and not fresh:
                now = self.clock()
                previous = self._again.get(key)
                refused = self._refused.get(key)
                if refused is not None and refused.reason == "journal":
                    # A later write invalidates the quiet window of a refused offer.
                    del self._refused[key]
                if previous is None and len(self._again) >= RECENT_CAP:
                    self._mark_owed()
                    return
                first = now
                if refused is not None and refused.first is not None:
                    first = refused.first
                if previous is not None:
                    first = previous.first
                self._again[key] = _Deferred(path, first, now)
                return
            if not fresh and self._seen_recently(key):
                return  # twenty processes of one program are one file to scan
            self._submit_offer(path, reason, fresh)

    def _seen_recently(self, key: str) -> bool:
        now = self.clock()
        last = self._recent.get(key)
        if last is not None and now - last < RECENT_SECONDS:
            return True
        self._recent[key] = now
        self._recent.move_to_end(key)
        while len(self._recent) > RECENT_CAP:
            self._recent.popitem(last=False)
        return False

    def _mark_owed(self) -> None:
        self._owed = True
        self._debt_version += 1

    def owe(self) -> None:
        with self._lock:
            self._mark_owed()

    def _submit_offer(self, path: str, reason: str, fresh: bool, first: float | None = None) -> bool:
        if self.submit(path, reason, fresh):
            self.counts[f"queued_{reason}"] += 1
            return True
        self.counts["queue_full"] += 1
        self._mark_owed()
        key = ntpath.normcase(path)
        previous = self._refused.get(key)
        if previous is not None and previous.reason == "process" and reason != "process":
            return False
        if previous is not None and previous.reason == reason:
            fresh = fresh or previous.fresh
            if first is None:
                first = previous.first
        if previous is None and len(self._refused) >= REFUSED_CAP and reason == "process":
            for older_key, older in self._refused.items():
                if older.reason != "process":
                    del self._refused[older_key]
                    break
        if previous is not None or len(self._refused) < REFUSED_CAP:
            self._refused[key] = _Refused(path, reason, fresh, first)
        return False

    def _retry_refused(self, *, journal: bool = True, keys: set[str] | None = None) -> None:
        with self._lock:
            # A running image takes precedence when the observed lane has room again.
            items = list(self._refused.items())
            items.sort(key=lambda item: item[1].reason != "process")
            for key, item in items:
                if keys is not None and key not in keys:
                    continue
                if item.reason == "journal" and not journal:
                    continue
                if self.submit(item.path, item.reason, item.fresh):
                    del self._refused[key]
                    self.counts[f"queued_{item.reason}"] += 1
                else:
                    self.counts["queue_full"] += 1
                    self._mark_owed()
                    break

    def _offer_again(self) -> None:
        with self._lock:
            now = self.clock()
            for key, item in list(self._again.items()):
                if now - item.last >= RECENT_SECONDS or now - item.first >= MAX_QUIET_SECONDS:
                    del self._again[key]
                    self._submit_offer(item.path, "journal", False, item.first)

    def tick_journal(self) -> None:
        retry_lookup = tuple(self._lookup_failures)
        volumes = self.volumes[self._next_volume:] + self.volumes[:self._next_volume]
        if self.volumes:
            self._next_volume = (self._next_volume + 1) % len(self.volumes)
        batch_budget = MAX_BATCHES_PER_TICK
        for volume in volumes:
            if not batch_budget:
                break
            previous_usn: int | None = None
            for _ in range(batch_budget):
                batch_budget -= 1
                batch = read_batch(volume.root, volume, self.store, volume.resolve)
                self.counts["records"] += len(batch.records)
                self.counts["unresolved"] += batch.unresolved
                self.counts["lookup_failed"] += batch.lookup_failed
                for record in batch.failed_records:
                    key = (volume.root, record.file_ref)
                    if key not in self._lookup_failures:
                        if len(self._lookup_failures) >= LOOKUP_CAP:
                            self._mark_owed()
                        else:
                            self._lookup_failures[key] = (volume, record, 1)
                for change in batch.records:
                    self._lookup_failures.pop((volume.root, change.record.file_ref), None)
                    if self.wanted(change.path):
                        self._offer(change.path, "journal")
                if batch.gaps:
                    for gap in batch.gaps:
                        self.counts[f"gap_{gap.reason}"] += 1
                    # A volume with no journal says so every tick: one incident, not one a tick.
                    reason = batch.gaps[0].reason
                    if self._gap_of.get(volume.root) != reason:
                        self._gap_of[volume.root] = reason
                        if any(gap.reconciliation_required for gap in batch.gaps):
                            with self._lock:
                                self._mark_owed()
                    reset_cursor(volume.root, volume, self.store)
                    break
                self._gap_of.pop(volume.root, None)
                if (batch.cursor is None or batch.cursor.next_usn >= batch.journal_end or
                        batch.cursor.next_usn == previous_usn):
                    break
                previous_usn = batch.cursor.next_usn
        for key in retry_lookup:
            pending = self._lookup_failures.get(key)
            if pending is None:
                continue
            volume, record, failures = pending
            try:
                path = volume.resolve(record)
            except OSError:
                self.counts["lookup_failed"] += 1
                if failures >= 2:
                    del self._lookup_failures[key]
                    self._mark_owed()
                else:
                    self._lookup_failures[key] = (volume, record, failures + 1)
            else:
                del self._lookup_failures[key]
                if path is not None and self.wanted(path):
                    self._offer(path, "journal")
        self._retry_refused()
        self._offer_again()
        now = self.clock()
        if self._owed and now - self._reconciled_at >= RECONCILE_SECONDS:
            # After the cursors moved: whatever changes during this scan is in the journal.
            self._reconciled_at = now
            self.counts["reconciliations"] += 1
            debt_version = self._debt_version
            finished = False
            try:
                finished = self.reconcile() is not False
            finally:
                with self._lock:
                    self._owed = not finished or self._debt_version != debt_version

    def tick_processes(self) -> None:
        if self.processes is None:
            return
        with self._lock:
            refused_before_poll = set(self._refused)
        self.processes.poll()
        while (target := self.processes.pop()) is not None:
            first = self.rescans is not None and self.rescans.first_run(target.identity)
            if first or not winfile.is_protected(target.path):
                self._offer(target.path, "process", fresh=first)
        self._retry_refused(journal=False, keys=refused_before_poll)

    def report(self) -> dict[str, Any]:
        with self._lock:
            out: dict[str, Any] = {"prevention": "none", "lookup_failed": 0, **self.counts,
                                   "refused_paths": len(self._refused)}
        if self.processes is not None:
            seen = self.processes.report
            out.update(process_observation=seen.process_observation, failed_polls=seen.failed_polls,
                       inaccessible_images=seen.inaccessible_images, exits_before_resolution=seen.exits_before_resolution,
                       largest_gap=round(seen.largest_gap, 3), queue_saturation=seen.queue_saturation)
        return out

    # -- threads

    def _loop(self, tick: Callable[[], None], seconds: float) -> None:
        while not self._stop.wait(seconds):
            try:
                tick()
            except Exception:
                log.exception("observer failed")

    def start(self) -> None:
        for name, tick, seconds in (("journal", self.tick_journal, JOURNAL_SECONDS),
                                    ("processes", self.tick_processes, self.processes.interval if self.processes else 0)):
            if seconds:
                thread = threading.Thread(target=self._loop, args=(tick, seconds), name=f"observe-{name}", daemon=True)
                self._threads.append(thread)
                thread.start()

    def stop(self) -> None:
        self._stop.set()
