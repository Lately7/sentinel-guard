"""On-demand scans (file, folder, whole machine) with progress and cancel, independent of any UI."""

from __future__ import annotations

import logging
import os
import string
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .db import Database
from .engine.scanner import Scanner
from .engine.verdict import CLEAN, MALICIOUS, Verdict
from .gate_v2 import scope
from .gate_v2.legacy import UNKNOWN
from .protection import act_on

log = logging.getLogger(__name__)

# Layer outcomes that mean the layer really looked at the bytes.
CHECKED = ("clean", "detected", "partial")


def fixed_drives() -> list[str]:
    if os.name != "nt":
        return ["/"]
    import ctypes

    k32 = ctypes.windll.kernel32
    mask = k32.GetLogicalDrives()
    out = []
    for i, letter in enumerate(string.ascii_uppercase):
        if mask & (1 << i):
            root = f"{letter}:\\"
            if k32.GetDriveTypeW(root) == 3:  # DRIVE_FIXED: skip network, optical and removable media
                out.append(root)
    return out


def _skip_dirs() -> set[str]:
    # The agent's own data holds the quarantine (inert, but still the bytes of
    # threats) and ClamAV's signature database; scanning them only produces noise.
    return {os.path.normcase(str(config.data_dir()))}


def discovery(profile: str, settings: config.Settings) -> scope.Discovery:
    """What a smart or deep scan covers: autostart, what is running, the watched folders."""
    return scope.discover(profile, scope.windows_sources(profile, list(settings.watch_dirs)),
                          data_root=str(config.data_dir()))


def walk(paths: list[str], cancel: threading.Event, errors: list[str] | None = None) -> Iterator[str]:
    skip = _skip_dirs()
    for base in paths:
        if cancel.is_set():
            return
        if os.path.isfile(base):
            yield base
            continue

        def onerror(e: OSError) -> None:
            if errors is not None and len(errors) < 1000:
                errors.append(f"{e.filename}: {e.strerror}")

        for root, dirs, files in os.walk(base, onerror=onerror):
            if cancel.is_set():
                return
            # Junctions and symlinked folders would loop (Application Data ->
            # AppData) or leave the chosen tree; their targets are walked on their own.
            dirs[:] = [d for d in dirs
                       if not _is_link(os.path.join(root, d))
                       and os.path.normcase(os.path.join(root, d)) not in skip]
            for f in files:
                yield os.path.join(root, f)


def _is_link(p: str) -> bool:
    try:
        return os.path.islink(p) or os.path.isjunction(p)
    except OSError:
        return True


@dataclass
class ScanProgress:
    title: str
    paths: list[str]
    started: float = field(default_factory=time.time)
    finished: float | None = None
    scanned: int = 0
    detections: int = 0  # threats + suspicious
    threats: int = 0
    suspicious: int = 0
    quarantined: int = 0
    unreadable: int = 0
    # Files no external engine (ClamAV/Defender) confirmed: a clean label for
    # these rests on the built-in checks alone.
    unverified: int = 0
    unknown: int = 0  # a required check did not finish: neither clean nor a threat
    current: str = ""
    cancelled: bool = False
    errors: list[str] = field(default_factory=list)
    # Sources a smart or deep scan could not look at, by reason: never the same as nothing there.
    uncovered: dict[str, int] = field(default_factory=dict)

    @property
    def running(self) -> bool:
        return self.finished is None

    def rate(self) -> float:
        dt = (self.finished or time.time()) - self.started
        return self.scanned / dt if dt > 0 else 0.0


class ScanJob:
    def __init__(self, scanner: Scanner, db: Database, settings: config.Settings, paths: list[str], title: str,
                 on_result: Callable[[dict, dict], None] | None = None,
                 on_done: Callable[[ScanProgress], None] | None = None,
                 found: scope.Discovery | None = None) -> None:
        self.scanner = scanner
        self.found = found
        self.db = db
        self.settings = settings
        self.progress = ScanProgress(title, list(paths))
        self.cancel_event = threading.Event()
        self.on_result = on_result
        self.on_done = on_done
        self._thread = threading.Thread(target=self._run, name="scan-job", daemon=True)

    def start(self) -> "ScanJob":
        self._thread.start()
        return self

    def cancel(self) -> None:
        self.cancel_event.set()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    def _files(self) -> Iterator[str]:
        if self.found is None:
            yield from walk(self.progress.paths, self.cancel_event, self.progress.errors)
            return
        for target in self.found:
            if self.cancel_event.is_set():
                return
            yield target.path

    def _run(self) -> None:
        p = self.progress
        try:
            for f in self._files():
                p.current = f
                try:
                    v = self.scanner.scan_file(f)
                except Exception as e:  # one hostile file must not end the whole scan
                    log.exception("scan of %s failed", f)
                    p.errors.append(f"{f}: {e}")
                    continue
                p.scanned += 1
                self._account(v)
            p.cancelled = self.cancel_event.is_set()
        finally:
            if self.found is not None:
                p.uncovered = {reason: n for reason, n in self.found.report.reasons.items()
                               if reason not in scope.NOT_A_GAP}
            p.finished = time.time()
            p.current = ""
            level = "warning" if p.detections else "info"
            self.db.add_event("scan", level, "Đã dừng quét" if p.cancelled else "Quét xong",
                              f"{p.title}: {p.scanned} tệp, {p.detections} phát hiện, {p.quarantined} đã cách ly",
                              {"paths": p.paths, "unverified": p.unverified, "unreadable": p.unreadable,
                               "unknown": p.unknown, "uncovered": p.uncovered})
            if self.on_done:
                self.on_done(p)

    def _account(self, v: Verdict) -> None:
        p = self.progress
        if v.skipped and v.skipped.startswith(("unreadable", "changed while")):
            p.unreadable += 1
        elif "allowlist" not in v.engines and not any(
                v.engines.get(k, "").startswith(CHECKED) for k in ("clamav", "defender")):
            p.unverified += 1
        if v.label == CLEAN:
            return
        if v.label == UNKNOWN:
            p.unknown += 1
            act_on(self.db, v, self.settings, "scan")
            return
        p.detections += 1
        if v.label == MALICIOUS:
            p.threats += 1
        else:
            p.suspicious += 1
        outcome = act_on(self.db, v, self.settings, "scan")
        if outcome["quarantined"]:
            p.quarantined += 1
        if self.on_result:
            self.on_result(v.to_dict(), outcome)


def describe_paths(paths: list[str]) -> str:
    return ", ".join(Path(x).name or x for x in paths[:3]) + (" …" if len(paths) > 3 else "")
