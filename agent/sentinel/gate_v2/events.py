"""In-memory progress snapshots and admission-bounded terminal events.

Milestone 7 must persist terminal records before acknowledging publication,
replay them after restart, and retain sequence allocation across restarts.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from threading import Condition
from typing import Protocol

from .contract import EVENT_VERSION, ScanEvent


class _Cancellation(Protocol):
    def cancelled(self) -> bool: ...


@dataclass(frozen=True)
class EventSnapshot:
    progress: tuple[ScanEvent, ...]
    terminal: tuple[ScanEvent, ...]
    counters: tuple[tuple[str, int], ...]
    coalesced: int


class EventStream:
    def __init__(self, scan_id: str, *, progress_capacity: int = 256, terminal_capacity: int = 4096) -> None:
        if progress_capacity < 1 or terminal_capacity < 1:
            raise ValueError("event capacities must be positive")
        self.scan_id = scan_id
        self.progress_capacity = progress_capacity
        self.terminal_capacity = terminal_capacity
        self._lock = Condition()
        self._sequence = 0
        self._progress: OrderedDict[tuple[str | None, str], ScanEvent] = OrderedDict()
        self._terminal: deque[ScanEvent] = deque()
        self._reserved: dict[str, int] = {}
        self._counters: dict[str, int] = {}
        self._coalesced = 0

    def admit(self, file_id: str, *, terminal_slots: int) -> bool:
        if terminal_slots < 1:
            raise ValueError("terminal_slots must be positive")
        with self._lock:
            if file_id in self._reserved or len(self._terminal) + sum(self._reserved.values()) + terminal_slots > self.terminal_capacity:
                return False
            self._reserved[file_id] = terminal_slots
            return True

    def wait_for_admission(self, file_id: str, *, terminal_slots: int,
                           cancel: _Cancellation | None = None) -> bool:
        if terminal_slots < 1:
            raise ValueError("terminal_slots must be positive")
        with self._lock:
            # More than the whole capacity: draining will never make room.
            if terminal_slots > self.terminal_capacity:
                return False
            while True:
                if cancel is not None and cancel.cancelled():
                    return False
                if (file_id not in self._reserved and
                    len(self._terminal) + sum(self._reserved.values()) + terminal_slots <= self.terminal_capacity):
                    self._reserved[file_id] = terminal_slots
                    return True
                self._lock.wait(timeout=0.05)

    def release(self, file_id: str) -> None:
        with self._lock:
            self._reserved.pop(file_id, None)
            self._lock.notify_all()

    def count(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + amount

    def publish(
        self, file_id: str | None, stage: str, state: str, result_code: str,
        *, duration_ms: int | None = None, terminal: bool = False,
    ) -> ScanEvent:
        with self._lock:
            if terminal and (file_id is None or self._reserved.get(file_id, 0) < 1):
                raise RuntimeError("terminal event requires admission")
            event = ScanEvent(EVENT_VERSION, self.scan_id, file_id, self._sequence,
                              stage, state, duration_ms, result_code)
            self._sequence += 1
            if terminal:
                self._reserved[file_id] -= 1
                self._terminal.append(event)
            else:
                key = (file_id, stage)
                if key in self._progress:
                    self._coalesced += 1
                    del self._progress[key]
                elif len(self._progress) >= self.progress_capacity:
                    self._coalesced += 1
                    self._progress.popitem(last=False)
                self._progress[key] = event
            return event

    def snapshot(self) -> EventSnapshot:
        with self._lock:
            return EventSnapshot(tuple(self._progress.values()), tuple(self._terminal),
                                 tuple(sorted(self._counters.items())), self._coalesced)

    def drain_terminal(self, limit: int | None = None) -> tuple[ScanEvent, ...]:
        with self._lock:
            count = len(self._terminal) if limit is None else min(limit, len(self._terminal))
            drained = tuple(self._terminal.popleft() for _ in range(count))
            if drained:
                self._lock.notify_all()
            return drained
