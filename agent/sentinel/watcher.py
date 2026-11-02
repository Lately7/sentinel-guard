"""Real-time protection: file-system watcher + autostart (persistence) monitor."""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from collections.abc import Callable
from pathlib import Path

from .config import Settings
from .db import Database
from .engine.scanner import Scanner
from .protection import act_on

log = logging.getLogger(__name__)

# Browsers and downloaders write to a temp name and rename when finished.
# Such files are scanned only after they have been quiet for a long while, so
# the normal case (renamed on completion) costs nothing, but a payload that
# keeps a temp-looking name still gets scanned eventually.
PARTIAL_SUFFIXES = (".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload", ".!ut")
SETTLE_SECONDS = 1.5
PARTIAL_SETTLE_SECONDS = 90.0
# Our own in-flight quarantine claims (see quarantine.py) must not be rescanned.
CLAIM_MARK = ".sentinel-"


class ScanQueue:
    """Debounces bursts of events per path and scans once the file stops changing."""

    def __init__(self, scanner: Scanner, db: Database, settings: Settings,
                 on_result: Callable[[dict], None] | None = None) -> None:
        self.scanner = scanner
        self.db = db
        self.settings = settings
        self.on_result = on_result
        self._pending: dict[str, float] = {}
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="scan-queue", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def submit(self, path: str) -> None:
        lowered = path.lower()
        if CLAIM_MARK in lowered and lowered.endswith(".claim"):
            return
        settle = PARTIAL_SETTLE_SECONDS if lowered.endswith(PARTIAL_SUFFIXES) else SETTLE_SECONDS
        with self._lock:
            # Stored as the moment the file becomes due; every new event pushes it back.
            self._pending[path] = time.monotonic() + settle
        self._wake.set()

    def _due(self) -> list[str]:
        now = time.monotonic()
        with self._lock:
            ready = [p for p, due in self._pending.items() if now >= due]
            for p in ready:
                del self._pending[p]
            if not self._pending:
                self._wake.clear()
        return ready

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=1.0)
            for path in self._due():
                if self._stop.is_set():
                    return
                self._scan_one(path)
            time.sleep(0.2)

    def _scan_one(self, path: str) -> None:
        if not os.path.isfile(path):
            return
        try:
            size1 = os.path.getsize(path)
            time.sleep(0.3)
            if os.path.getsize(path) != size1:  # still being written
                self.submit(path)
                return
            v = self.scanner.scan_file(path)
            if v.skipped == "changed while scanning":
                self.submit(path)
                return
            outcome = act_on(self.db, v, self.settings, "watcher")
            if outcome["error"] and "changed after it was scanned" in outcome["error"]:
                self.submit(path)
            if self.on_result:
                self.on_result({"verdict": v.to_dict(), **outcome})
        except Exception:
            log.exception("scan of %s failed", path)


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


def read_run_entries() -> dict[str, str]:
    if os.name != "nt":
        return {}
    import winreg

    out: dict[str, str] = {}
    for hive_name, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
        for key in RUN_KEYS:
            try:
                with winreg.OpenKey(hive, key) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(k, i)
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


class RealtimeProtection:
    def __init__(self, db: Database, settings: Settings, scanner: Scanner,
                 on_result: Callable[[dict], None] | None = None) -> None:
        self.queue = ScanQueue(scanner, db, settings, on_result)
        self.files = FileWatcher(self.queue, settings.watch_dirs)
        self.persistence = PersistenceMonitor(self.queue, db)
        self.running = False

    def start(self) -> None:
        self.queue.start()
        self.files.start()
        self.persistence.start()
        self.running = True

    def stop(self) -> None:
        self.files.stop()
        self.persistence.stop()
        self.queue.stop()
        self.running = False
