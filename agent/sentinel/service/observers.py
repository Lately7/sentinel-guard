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
from typing import Any, Protocol

from ..db import Database
from ..gate_v2 import winfile
from .procwatch import ProcessWatcher
from .rescan import RescanQueue
from .usn import Device, JournalCursor, UsnRecord, read_batch, reset_cursor

log = logging.getLogger(__name__)

JOURNAL_SECONDS = 5.0
RECENT_SECONDS = 10.0
RECENT_CAP = 4096
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
                 reconcile: Callable[[], None] = lambda: None, data_root: str = "",
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
        now = self.clock()
        key = ntpath.normcase(path)
        last = self._recent.get(key)
        if last is not None and now - last < RECENT_SECONDS and not fresh:
            return
        self._recent[key] = now
        self._recent.move_to_end(key)
        while len(self._recent) > RECENT_CAP:
            self._recent.popitem(last=False)
        if self.submit(path, reason, fresh):
            self.counts[f"queued_{reason}"] += 1
        else:
            self.counts["queue_full"] += 1

    def tick_journal(self) -> None:
        lost = False
        for volume in self.volumes:
            batch = read_batch(volume.root, volume, self.store, volume.resolve)
            self.counts["records"] += len(batch.records)
            self.counts["unresolved"] += batch.unresolved
            for change in batch.records:
                if self.wanted(change.path):
                    self._offer(change.path, "journal")
            for gap in batch.gaps:
                self.counts[f"gap_{gap.reason}"] += 1
                lost = lost or gap.reconciliation_required
            if batch.gaps:
                reset_cursor(volume.root, volume, self.store)
        if lost:
            # After the cursors moved: whatever changes during this scan is in the journal.
            self.counts["reconciliations"] += 1
            self.reconcile()

    def tick_processes(self) -> None:
        if self.processes is None:
            return
        self.processes.poll()
        while (target := self.processes.pop()) is not None:
            first = self.rescans is not None and self.rescans.first_run(target.identity)
            if first or not winfile.is_protected(target.path):
                self._offer(target.path, "process", fresh=first)

    def report(self) -> dict[str, Any]:
        out: dict[str, Any] = {"prevention": "none", **self.counts}
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
