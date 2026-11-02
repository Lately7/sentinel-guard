"""Background probe of slow engine states, so the UI never blocks on them.

Asking whether Defender is the active antivirus runs PowerShell (seconds; 16 s
measured on the owner's machine), and pinging a stopped clamd on Windows waits
for TCP retries (~2 s per ping). The dashboard reads the last snapshot; one
worker thread refreshes it.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from .engine import defender
from .engine.scanner import Scanner


@dataclass(frozen=True)
class Snapshot:
    checked: float = 0.0          # 0 = not probed yet
    defender_active: bool = False
    clamav_status: str = "checking"  # ClamAVEngine.status(), "off" when not configured
    clamav_version: str | None = None


class EngineStatus:
    def __init__(self, scanner: Scanner, on_change: Callable[[], None] | None = None, interval: float = 15.0) -> None:
        self.scanner = scanner
        self.on_change = on_change
        self.interval = interval
        self.snapshot = Snapshot(clamav_status="checking" if scanner.clamav is not None else "off")
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="engine-status", daemon=True)

    def start(self) -> "EngineStatus":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def refresh_soon(self) -> None:
        self._wake.set()

    def probe(self) -> Snapshot:
        eng = self.scanner.clamav
        status = eng.status() if eng is not None else "off"
        return Snapshot(
            checked=time.time(),
            defender_active=defender.available(),
            clamav_status=status,
            clamav_version=eng.version() if eng is not None and status == "ready" else None,
        )

    def _run(self) -> None:
        while not self._stop.is_set():
            old, snap = self.snapshot, self.probe()
            self.snapshot = snap
            # The first probe always notifies: the UI is still showing "checking".
            same = old.checked and (old.defender_active, old.clamav_status, old.clamav_version) == (
                snap.defender_active, snap.clamav_status, snap.clamav_version)
            if not same and self.on_change:
                self.on_change()
            self._wake.wait(self.interval)
            self._wake.clear()
