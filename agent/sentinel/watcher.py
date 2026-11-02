"""Real-time protection: file-system watcher + autostart (persistence) monitor."""

from __future__ import annotations

import dataclasses
import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

from .config import Settings
from .db import Database
from .engine.scanner import Scanner
from .engine.verdict import Verdict
from .gate_v2.actions import ProtectionBarrier, ProtectionStopped
from .gate_v2.legacy import UNKNOWN
from .protection import act_on

log = logging.getLogger(__name__)

# Browsers and downloaders write to a temp name and rename when finished.
# Such files are scanned only after they have been quiet for a long while, so
# the normal case (renamed on completion) costs nothing, but a payload that
# keeps a temp-looking name still gets scanned eventually.
PARTIAL_SUFFIXES = (".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload", ".!ut")
SETTLE_SECONDS = 1.5
PARTIAL_SETTLE_SECONDS = 90.0
# Every event pushes the quiet timer back, so a file that never stops changing
# would never be scanned; past this age it is scanned anyway (RT-017).
MAX_AGE_SECONDS = 30.0
PARTIAL_MAX_AGE_SECONDS = 600.0
# Upper bound on paths waiting to be scanned (RT-017). Beyond it events are
# counted and reported instead of growing memory without limit.
MAX_PENDING = 10_000
OVERFLOW_REPORT_SECONDS = 60.0
# A file another program holds open (download manager, installer, Office) is
# retried with growing delays: five attempts in about 40 s (RT-016, following
# docs/research/R12d-wazuh.md section 2). After that it is reported as
# unscanned; it is rescanned on its next change.
RETRY_DELAYS = (0.5, 2.0, 8.0, 30.0)
SIZE_RECHECK_SECONDS = 0.3
# How long stop() waits for an automatic action that is already running.
ACTION_BARRIER_SECONDS = 30.0


@dataclasses.dataclass
class _Pending:
    first_seen: float
    due: float
    attempts: int = 0  # failed reads of this file so far


class ScanQueue:
    """Debounces bursts of events per path and scans once the file stops changing."""

    def __init__(self, scanner: Scanner, db: Database, settings: Settings,
                 on_result: Callable[[dict], None] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.scanner = scanner
        self.db = db
        self.settings = settings
        self.on_result = on_result
        self._clock = clock
        self._pending: dict[str, _Pending] = {}
        self.dropped = 0  # events lost to MAX_PENDING since start
        self._dropped_unreported = 0
        self._overflow_reported_at = float("-inf")
        self._incomplete_unreported = 0
        self._incomplete_reported_at = float("-inf")
        self._lock = threading.Lock()
        # Every automatic action runs inside it; stop() revokes it, so no action
        # of this run can start afterwards or still be in progress (RT-018).
        self.barrier = ProtectionBarrier()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="scan-queue", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = ACTION_BARRIER_SECONDS) -> bool:
        """Stops new work and waits for an automatic action in progress.

        Returns False if an action was still running after `timeout`; it then
        finishes on its own, but no later action of this run can start.
        """
        with self._lock:
            self._stop.set()
            self._pending.clear()
        self._wake.set()
        return self.barrier.revoke(timeout)

    def submit(self, path: str) -> None:
        partial = path.lower().endswith(PARTIAL_SUFFIXES)
        settle = PARTIAL_SETTLE_SECONDS if partial else SETTLE_SECONDS
        max_age = PARTIAL_MAX_AGE_SECONDS if partial else MAX_AGE_SECONDS
        now = self._clock()
        with self._lock:
            if self._stop.is_set():
                return
            entry = self._pending.get(path)
            if entry is None:
                if len(self._pending) >= MAX_PENDING:
                    self.dropped += 1
                    self._dropped_unreported += 1
                    return
                self._pending[path] = _Pending(now, now + settle)
            else:
                # Every new event pushes the due time back, but never past max_age.
                entry.due = min(now + settle, entry.first_seen + max_age)
        self._wake.set()

    def _requeue(self, path: str, delay: float, attempts: int = 0) -> None:
        # A fresh entry: the file was just looked at, so its age starts again.
        now = self._clock()
        with self._lock:
            if self._stop.is_set() or path in self._pending:
                return
            if len(self._pending) >= MAX_PENDING:
                self.dropped += 1
                self._dropped_unreported += 1
                return
            self._pending[path] = _Pending(now, now + delay, attempts)
        self._wake.set()

    def _due(self) -> list[tuple[str, int]]:
        now = self._clock()
        with self._lock:
            ready = [(p, e.attempts) for p, e in self._pending.items() if now >= e.due]
            for p, _ in ready:
                del self._pending[p]
            if not self._pending:
                self._wake.clear()
        return ready

    def _report_overflow(self) -> None:
        now = self._clock()
        with self._lock:
            n = self._dropped_unreported
            if not n or now - self._overflow_reported_at < OVERFLOW_REPORT_SECONDS:
                return
            self._dropped_unreported = 0
            self._overflow_reported_at = now
        self.db.add_event("watcher", "warning", "Quá nhiều tệp thay đổi cùng lúc",
                          f"{n} thay đổi chưa được đưa vào hàng quét. Hãy chạy Quét ngay để kiểm tra lại.",
                          {"dropped": n})

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=1.0)
            self._report_overflow()
            self._report_incomplete()
            for path, attempts in self._due():
                if self._stop.is_set():
                    return
                try:
                    self._scan_one(path, attempts)
                except Exception:
                    log.exception("scan of %s failed", path)
            time.sleep(0.2)

    def _scan_one(self, path: str, attempts: int = 0) -> None:
        if not os.path.isfile(path):
            return
        try:
            size1 = os.path.getsize(path)
            time.sleep(SIZE_RECHECK_SECONDS)
            size2 = os.path.getsize(path)
        except OSError as e:
            self._unreadable(path, attempts, f"unreadable: {e.strerror or e}")
            return
        if size2 != size1:  # still being written
            self._requeue(path, SETTLE_SECONDS)
            return
        v = self.scanner.scan_file(path, use_cache=False)  # see db.cached_result
        if v.skipped == "changed while scanning":
            self._requeue(path, SETTLE_SECONDS)
            return
        if v.skipped and v.skipped.startswith("unreadable"):
            self._unreadable(path, attempts, v.skipped)
            return
        if v.label == UNKNOWN:
            self._incomplete(path, attempts)
        outcome = self._act(v)
        if outcome["error"] and "changed after it was scanned" in outcome["error"]:
            self._requeue(path, SETTLE_SECONDS)
        if self.on_result:
            self.on_result({"verdict": v.to_dict(), **outcome})

    def _incomplete(self, path: str, attempts: int) -> None:
        # A required engine did not finish (clamd restarting, a timeout): worth a
        # few more tries, and reported as a count, because when an engine is down
        # every file lands here.
        attempts += 1
        if attempts <= len(RETRY_DELAYS):
            self._requeue(path, RETRY_DELAYS[attempts - 1], attempts)
            return
        with self._lock:
            self._incomplete_unreported += 1

    def _report_incomplete(self) -> None:
        now = self._clock()
        with self._lock:
            n = self._incomplete_unreported
            if not n or now - self._incomplete_reported_at < OVERFLOW_REPORT_SECONDS:
                return
            self._incomplete_unreported = 0
            self._incomplete_reported_at = now
        self.db.add_event("watcher", "warning", "Có tệp chưa kiểm tra xong",
                          f"{n} tệp chưa được kiểm tra đủ vì một lớp quét chưa sẵn sàng. "
                          "Hãy chạy Quét ngay khi các lớp đã sẵn sàng.", {"files": n})

    def _unreadable(self, path: str, attempts: int, reason: str) -> None:
        attempts += 1
        if attempts <= len(RETRY_DELAYS):
            self._requeue(path, RETRY_DELAYS[attempts - 1], attempts)
            return
        # Not scanned is not clean: say so instead of dropping the file.
        self.db.add_event("watcher", "warning", "Chưa quét được tệp",
                          f"{Path(path).name}: tệp đang bị chương trình khác giữ hoặc không đọc được "
                          f"(đã thử {attempts} lần). Tệp sẽ được quét lại khi thay đổi; có thể chạy Quét ngay để thử lại.",
                          {"path": path, "reason": reason[:300], "attempts": attempts})

    def _act(self, v: Verdict) -> dict:
        try:
            with self.barrier.action():
                return act_on(self.db, v, self.settings, "watcher")
        except ProtectionStopped:
            # Switched off while this file was being scanned: the finding is
            # still recorded, but a stopped run must not quarantine (RT-018).
            return act_on(self.db, v, dataclasses.replace(self.settings, auto_quarantine=False), "watcher")


class FileWatcher:
    def __init__(self, scan_queue: ScanQueue, dirs: list[str]) -> None:
        from watchdog.events import FileSystemEvent, FileSystemEventHandler
        from watchdog.observers import Observer

        q = scan_queue

        class Handler(FileSystemEventHandler):
            def on_created(self, event: FileSystemEvent) -> None:
                if not event.is_directory:
                    q.submit(str(event.src_path))

            def on_modified(self, event: FileSystemEvent) -> None:
                if not event.is_directory:
                    q.submit(str(event.src_path))

            def on_moved(self, event: FileSystemEvent) -> None:
                if not event.is_directory:
                    q.submit(str(event.dest_path))

        self.observer = Observer()
        self.dirs: list[str] = []
        for d in dirs:
            if Path(d).is_dir():
                # Recursive on purpose: archives get extracted into subfolders.
                self.observer.schedule(Handler(), d, recursive=True)
                self.dirs.append(d)

    def start(self) -> None:
        self.observer.start()

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join(timeout=5)


RUN_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
]


def read_run_entries(reg=None) -> dict[str, str]:
    """Run/RunOnce values, keyed "HIVE\\key\\name".

    HKLM\\Software is split by WOW64: 32-bit installers register under the
    32-bit view (Wow6432Node), which a 64-bit process does not see by default,
    so both views are read ("HKLM" and "HKLM32"). HKCU\\Software is shared.
    `reg` is the winreg module, injectable for tests.
    """
    if reg is None:
        if os.name != "nt":
            return {}
        import winreg as reg

    views = (("HKCU", reg.HKEY_CURRENT_USER, 0),
             ("HKLM", reg.HKEY_LOCAL_MACHINE, reg.KEY_WOW64_64KEY),
             ("HKLM32", reg.HKEY_LOCAL_MACHINE, reg.KEY_WOW64_32KEY))
    out: dict[str, str] = {}
    for hive_name, hive, view in views:
        for key in RUN_KEYS:
            try:
                with reg.OpenKey(hive, key, 0, reg.KEY_READ | view) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _ = reg.EnumValue(k, i)
                        except OSError:
                            break
                        out[f"{hive_name}\\{key}\\{name}"] = str(value)
                        i += 1
            except OSError:
                continue
    return out


def command_target(command: str) -> str | None:
    """Executable path from a Run-key command line (quoted or not)."""
    command = os.path.expandvars(command.strip())
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 1 else None
    lowered = command.lower()
    for ext in (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk", ".com", ".scr"):
        i = lowered.find(ext)
        if i != -1:
            return command[: i + len(ext)]
    return command.split(" ", 1)[0] or None


def split_command_line(command: str) -> list[str]:
    """Windows argv splitting rules (CommandLineToArgvW), with a simple fallback."""
    if os.name == "nt" and command.strip():
        import ctypes
        from ctypes import wintypes

        shell32 = ctypes.WinDLL("shell32")
        shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
        shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
        argc = ctypes.c_int(0)
        argv = shell32.CommandLineToArgvW(command, ctypes.byref(argc))
        if argv:
            try:
                return [argv[i] for i in range(argc.value)]
            finally:
                ctypes.windll.kernel32.LocalFree(argv)
    return command.split()


def command_files(command: str) -> list[str]:
    """Every existing local file a Run-key command refers to: the program and
    any script/library passed to it (an interpreter is rarely the payload)."""
    expanded = os.path.expandvars(command.strip())
    files: list[str] = []
    first = command_target(expanded)
    if first and os.path.isfile(first):
        files.append(first)
    for tok in split_command_line(expanded):
        for cand in (tok, tok.split(",", 1)[0], tok.partition("=")[2], tok.partition(":")[2] if tok.startswith("/") else ""):
            cand = cand.strip().strip('"')
            if cand and len(cand) > 3 and os.path.isfile(cand) and cand not in files:
                files.append(cand)
    return files


class PersistenceMonitor:
    """Polls autostart registry keys; new entries are reported and their targets scanned."""

    def __init__(self, scan_queue: ScanQueue, db: Database, interval: float = 15.0) -> None:
        self.q = scan_queue
        self.db = db
        self.interval = interval
        self._known = read_run_entries()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="persistence", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                current = read_run_entries()
            except Exception:
                log.exception("reading Run keys failed")
                continue
            for name, cmd in current.items():
                if self._known.get(name) == cmd:
                    continue
                self.db.add_event("persistence", "warning", "Chương trình mới tự khởi động cùng Windows",
                                  f"{name.rsplit(chr(92), 1)[-1]}: {cmd}", {"key": name, "command": cmd})
                for target in command_files(cmd):
                    self.q.submit(target)
            self._known = current


class NothingToWatch(RuntimeError):
    """None of the configured folders exists; real-time protection would watch nothing."""


class RealtimeProtection:
    def __init__(self, db: Database, settings: Settings, scanner: Scanner,
                 on_result: Callable[[dict], None] | None = None) -> None:
        self.queue = ScanQueue(scanner, db, settings, on_result)
        self.files = FileWatcher(self.queue, settings.watch_dirs)
        self.persistence = PersistenceMonitor(self.queue, db)
        self.running = False

    def start(self) -> None:
        # Reporting "on" while no folder is watched would be a false sense of
        # protection; the caller shows the error instead.
        if not self.files.dirs:
            raise NothingToWatch("không có thư mục nào để theo dõi (các thư mục đã cấu hình không tồn tại)")
        self.queue.start()
        self.files.start()
        self.persistence.start()
        self.running = True

    def stop(self, timeout: float = ACTION_BARRIER_SECONDS) -> bool:
        """False if an automatic action was still finishing when stop gave up waiting."""
        # Watchers first, so nothing new is submitted while the queue drains.
        self.files.stop()
        self.persistence.stop()
        closed = self.queue.stop(timeout)
        self.running = False
        return closed
