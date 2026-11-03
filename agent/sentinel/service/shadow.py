"""Bounded, observation-only ETW burst study."""

from __future__ import annotations

import json
import math
import ntpath
import os
import threading
import time
from pathlib import Path
from typing import Callable

from . import burst
from .etw import ParsedEvent

MAX_LOG_BYTES = 256 * 1024
MAX_IMAGE = 128
MAX_IDLE_SECONDS = 300.0
NAME_TTL_SECONDS = 10.0
DOCUMENT_SUFFIXES = frozenset({
    ".txt", ".csv", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".odt", ".ods", ".rtf", ".jpg", ".jpeg", ".png", ".gif",
})


class RollingDecisionLog:
    """Keep complete newest JSON lines in the protected state journal."""

    def __init__(self, state_root: Path, *, max_bytes: int = MAX_LOG_BYTES) -> None:
        if not 512 <= max_bytes <= MAX_LOG_BYTES:
            raise ValueError("invalid log bound")
        self.path = Path(state_root) / "journal" / "shadow-decisions.jsonl"
        self.checkpoint_path = Path(state_root) / "journal" / "shadow-observation.json"
        self.max_bytes = max_bytes

    def append(self, entry: dict[str, object]) -> None:
        line = (json.dumps(entry, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        if len(line) > self.max_bytes:
            raise ValueError("log entry exceeds bound")
        previous = b""
        try:
            with self.path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                if size + len(line) <= self.max_bytes:
                    with self.path.open("ab") as output:
                        output.write(line)
                    return
                offset = max(0, size - self.max_bytes)
                stream.seek(offset)
                previous = stream.read(self.max_bytes)
                if offset:
                    previous = previous.partition(b"\n")[2]
        except FileNotFoundError:
            pass
        lines = previous.splitlines(keepends=True)
        if lines and not lines[-1].endswith(b"\n"):
            lines.pop()
        lines.append(line)
        while sum(map(len, lines)) > self.max_bytes:
            lines.pop(0)
        temporary = self.path.with_suffix(".tmp")
        try:
            with temporary.open("wb") as stream:
                stream.writelines(lines)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def load_checkpoint(self) -> dict[str, object] | None:
        try:
            with self.checkpoint_path.open("rb") as stream:
                data = stream.read(1025)
            if len(data) > 1024:
                return None
            value = json.loads(data)
            return value if isinstance(value, dict) else None
        except (FileNotFoundError, OSError, ValueError, UnicodeError):
            return None

    def save_checkpoint(self, value: dict[str, object]) -> None:
        data = json.dumps(value, separators=(",", ":")).encode("ascii")
        if len(data) > 1024:
            raise ValueError("checkpoint exceeds bound")
        temporary = self.checkpoint_path.with_suffix(".tmp")
        try:
            with temporary.open("wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.checkpoint_path)
        finally:
            temporary.unlink(missing_ok=True)


class ShadowObserver:
    """Score ETW requests provisionally; no result authorizes a process action."""

    def __init__(self, document_roots: tuple[str, ...] = (), *,
                 writer: Callable[[dict[str, object]], None] | None = None,
                 state_root: Path | None = None,
                 image_name: Callable[[int, int], str | None] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time) -> None:
        if writer is None and state_root is None:
            raise ValueError("state_root or writer required")
        self._log = RollingDecisionLog(state_root) if writer is None else None
        self._writer = writer if writer is not None else self._log.append
        self._image_name = image_name
        self._clock, self._wall_clock = clock, wall_clock
        self._roots = tuple(ntpath.normcase(ntpath.normpath(root)).rstrip("\\") + "\\"
                            for root in document_roots if isinstance(root, str) and root)
        self._lock = threading.RLock()
        self._scores = burst.Incident()
        self._scores.enable()
        self._names: dict[int, tuple[str, float]] = {}
        self._processes: dict[int, tuple[int, str]] = {}
        self._first_seen: float | None = None
        self._last_event: float | None = None
        self._observed_seconds = 0.0
        self._events_fed = 0
        self._read_write_events = 0
        self._usable_read_write_events = 0
        self._unattributed_file = 0
        self._unattributed_process = 0
        self._inferred_processes = 0
        self._evicted_names = 0
        self._evicted_processes = 0
        self._expired_names = 0
        self._decisions_not_logged = 0
        self._would_have_suspended = 0
        self._provisional_alerts = 0
        self._gaps = 0
        self._log_errors = 0
        self._in_gap = False
        self._last_checkpoint: float | None = None
        if self._log is not None:
            saved = self._log.load_checkpoint()
            if saved is not None:
                if self._restore(saved):
                    self._gap("downtime")

    def _restore(self, saved: dict[str, object]) -> bool:
        floats = ("first_seen", "observed_seconds")
        integers = ("events_fed", "would_have_suspended", "provisional_alerts", "gaps", "log_errors")
        optional_integers = ("read_write_events", "usable_read_write_events",
                             "unattributed_file", "unattributed_process", "inferred_processes",
                             "evicted_names", "evicted_processes", "expired_names",
                             "decisions_not_logged")
        if (saved.get("version") != 1
                or any(not isinstance(saved.get(key), (int, float))
                       or not math.isfinite(saved[key]) or saved[key] < 0 for key in floats)
                or any(type(saved.get(key)) is not int or saved[key] < 0 for key in integers)
                or any(type(saved.get(key, 0)) is not int or saved[key] < 0
                       for key in optional_integers if key in saved)):
            self._gap("checkpoint_invalid")
            return False
        self._first_seen = float(saved["first_seen"])
        self._observed_seconds = float(saved["observed_seconds"])
        self._events_fed = int(saved["events_fed"])
        for key in optional_integers:
            setattr(self, f"_{key}", int(saved.get(key, 0)))
        self._would_have_suspended = int(saved["would_have_suspended"])
        self._provisional_alerts = int(saved["provisional_alerts"])
        self._gaps = int(saved["gaps"])
        self._log_errors = int(saved["log_errors"])
        return True

    def _checkpoint(self, now: float, *, force: bool = False) -> None:
        if self._log is None or self._first_seen is None:
            return
        if not force and self._last_checkpoint is not None and now - self._last_checkpoint < 60:
            return
        value: dict[str, object] = {"version": 1, "first_seen": self._first_seen,
                                    "observed_seconds": self._observed_seconds,
                                    "events_fed": self._events_fed,
                                    "read_write_events": self._read_write_events,
                                    "usable_read_write_events": self._usable_read_write_events,
                                    "unattributed_file": self._unattributed_file,
                                    "unattributed_process": self._unattributed_process,
                                    "inferred_processes": self._inferred_processes,
                                    "evicted_names": self._evicted_names,
                                    "evicted_processes": self._evicted_processes,
                                    "expired_names": self._expired_names,
                                    "decisions_not_logged": self._decisions_not_logged,
                                    "would_have_suspended": self._would_have_suspended,
                                    "provisional_alerts": self._provisional_alerts,
                                    "gaps": self._gaps, "log_errors": self._log_errors}
        try:
            self._log.save_checkpoint(value)
            self._last_checkpoint = now
        except (OSError, ValueError):
            self._log_errors += 1
            self._gap("checkpoint_write_failed")

    def _emit(self, entry: dict[str, object]) -> None:
        try:
            self._writer(entry)
        except (OSError, ValueError):
            self._log_errors += 1
            self._gap("log_write_failed", log=False)

    def _gap(self, reason: str, *, log: bool = True) -> None:
        if not self._in_gap:
            self._gaps += 1
            self._in_gap = True
            if log:
                self._emit({"time": self._wall_clock(), "kind": "gap", "reason": reason})
        self._scores = burst.Incident()
        self._scores.enable()
        self._names.clear()
        self._processes.clear()
        if reason != "checkpoint_write_failed":
            self._checkpoint(self._clock(), force=True)

    def record_gap(self, reason: str = "collector_loss") -> None:
        """The ETW owner calls this for loss, downtime, or unavailable coverage."""
        with self._lock:
            self._gap(reason if reason in ("collector_loss", "collector_unavailable", "downtime")
                      else "collector_loss")
            self._last_event = None

    def _image(self, pid: int, creation_time: int) -> str:
        if self._image_name is None:
            return "unknown"
        try:
            value = self._image_name(pid, creation_time)
        except (OSError, ValueError):
            return "unknown"
        if not isinstance(value, str):
            return "unknown"
        name = ntpath.basename(value.replace("/", "\\"))
        if not name or any(ord(char) < 32 for char in name):
            return "unknown"
        return name[:MAX_IMAGE]

    def _owner_document(self, path: str) -> bool:
        normalized = ntpath.normcase(ntpath.normpath(path))
        return (any(normalized.startswith(root) for root in self._roots)
                and ntpath.splitext(normalized)[1] in DOCUMENT_SUFFIXES)

    def _expire_names(self, now: float) -> None:
        while self._names:
            oldest = next(iter(self._names))
            if now - self._names[oldest][1] <= NAME_TTL_SECONDS:
                break
            del self._names[oldest]
            self._expired_names += 1

    def _make_process(self, pid: int, creation_time: int) -> None:
        self._scores.forget_process(pid)
        self._processes.pop(pid, None)
        if len(self._processes) >= burst.MAX_PROCESSES:
            oldest = next(iter(self._processes))
            del self._processes[oldest]
            self._scores.forget_process(oldest)
            self._evicted_processes += 1
        self._processes[pid] = (creation_time, self._image(pid, creation_time))

    def feed(self, event: ParsedEvent, *, confirmed_canary: bool = False,
             strong_attribution: bool = False) -> None:
        """Optional canary proof is reserved for a future verified source."""
        with self._lock:
            now = self._clock()
            wall = self._wall_clock()
            if self._first_seen is None:
                self._first_seen = wall
            if self._last_event is not None:
                delta = now - self._last_event
                if delta < 0 or delta > MAX_IDLE_SECONDS:
                    self._gap("observation_interrupted")
                else:
                    self._observed_seconds += delta
            self._last_event = now
            self._events_fed += 1
            self._checkpoint(now)
            if (not isinstance(event, ParsedEvent) or not isinstance(event.kind, str)
                    or type(event.pid) is not int or type(event.file_object) is not int
                    or type(event.creation_time) is not int):
                self._gap("malformed_event")
                return
            if confirmed_canary and not strong_attribution:
                self._gap("canary_attribution_missing")
                return
            self._expire_names(now)
            if event.kind == "process_start":
                if event.pid <= 4 or event.creation_time <= 0:
                    self._unattributed_process += 1
                    return
                self._make_process(event.pid, event.creation_time)
                return
            if event.kind == "process_stop":
                self._processes.pop(event.pid, None)
                self._scores.forget_process(event.pid)
                return
            if event.kind == "name":
                if (not isinstance(event.path, str) or not event.path
                        or len(event.path) > burst.MAX_PATH or event.file_object <= 0):
                    self._unattributed_file += 1
                    return
                self._names.pop(event.file_object, None)
                if len(self._names) >= burst.MAX_FILE_OBJECTS:
                    del self._names[next(iter(self._names))]
                    self._evicted_names += 1
                self._names[event.file_object] = (event.path, now)
                return
            if event.kind not in ("read", "write"):
                self._gap("unknown_event")
                return
            self._read_write_events += 1
            if event.pid <= 4:
                self._unattributed_process += 1
                return
            process = self._processes.get(event.pid)
            if process is None:
                self._make_process(event.pid, 0)
                self._inferred_processes += 1
                process = self._processes[event.pid]
            named = self._names.get(event.file_object)
            if named is None:
                self._unattributed_file += 1
                return
            self._usable_read_write_events += 1
            path = named[0]
            if not self._owner_document(path):
                return
            self._in_gap = False
            # ETW requests do not prove a changed byte or a live process identity.
            operation = burst.Operation(now, event.pid, process[0], path,
                                        ntpath.dirname(path), event.kind,
                                        owner_document=True,
                                        canary=confirmed_canary,
                                        confirmed=confirmed_canary,
                                        attributed=True)
            prior_state = self._scores.state
            decision = self._scores.observe(operation, shadow=True)
            if decision.state == burst.State.GAP:
                self._decisions_not_logged += 1
                self._gap("score_gap")
            else:
                would_suspend = (decision.alert and decision.state == burst.State.VERIFIED
                                 and decision.reason == "corroborated_canary")
                if decision.alert:
                    self._provisional_alerts += 1
                    if would_suspend:
                        self._would_have_suspended += 1
                if decision.alert or decision.state != prior_state:
                    self._emit({"time": wall, "kind": "decision", "image": process[1],
                                "documents": decision.distinct_documents,
                                "folders": decision.directories, "state": decision.state.value,
                                "reason": decision.reason,
                                "would_suspend": would_suspend})
                else:
                    self._decisions_not_logged += 1
                if decision.alert:
                    self._checkpoint(now, force=True)

    def report(self) -> dict[str, object]:
        with self._lock:
            return {"first_seen": self._first_seen,
                    "days_observed": self._observed_seconds / 86400.0,
                    "events_fed": self._events_fed,
                    "read_write_events": self._read_write_events,
                    "usable_read_write_events": self._usable_read_write_events,
                    "usable_io_share": (self._usable_read_write_events / self._read_write_events
                                        if self._read_write_events else None),
                    "unattributed_file": self._unattributed_file,
                    "unattributed_process": self._unattributed_process,
                    "inferred_processes": self._inferred_processes,
                    "evicted_names": self._evicted_names,
                    "evicted_processes": self._evicted_processes,
                    "expired_names": self._expired_names,
                    "decisions_not_logged": self._decisions_not_logged,
                    "would_have_suspended": self._would_have_suspended,
                    "would_have_suspended_limit": "requires_confirmed_canary_not_supplied_by_etw",
                    "provisional_alerts": self._provisional_alerts,
                    "gaps": self._gaps, "log_errors": self._log_errors,
                    "window_seconds": burst.WINDOW_SECONDS,
                    "burst_documents": burst.BURST_DOCUMENTS,
                    "burst_directories": burst.BURST_DIRECTORIES,
                    "evidence": "unconfirmed_etw_requests"}
