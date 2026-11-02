"""Bounded download rescan debt keyed by file identity and gate generation (A5).

A download judged by today's rules is judged again when the rules change and
when it first runs: that is when a sample too new for the lists gets caught.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Protocol

from ..db import Database


@dataclass(frozen=True)
class Download:
    volume: int
    file_id: int
    path: str
    sha256: str
    gate_generation: str
    recorded_at: float
    first_run_seen: bool = False

    @property
    def identity(self) -> tuple[int, int]:
        return self.volume, self.file_id


class DownloadStore(Protocol):
    def get(self, identity: tuple[int, int]) -> Download | None: ...
    def put(self, item: Download) -> None: ...
    def delete(self, identity: tuple[int, int]) -> None: ...
    def values(self) -> tuple[Download, ...]: ...


class MemoryDownloadStore:
    def __init__(self) -> None:
        self._items: dict[tuple[int, int], Download] = {}

    def get(self, identity: tuple[int, int]) -> Download | None:
        return self._items.get(identity)

    def put(self, item: Download) -> None:
        self._items[item.identity] = item

    def delete(self, identity: tuple[int, int]) -> None:
        self._items.pop(identity, None)

    def values(self) -> tuple[Download, ...]:
        return tuple(self._items.values())


class DbDownloadStore:
    """Survives restarts: a rule update overnight must still find yesterday's downloads."""

    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _item(row: dict[str, object]) -> Download:
        return Download(int(row["volume"]), int(row["file_id"]), str(row["path"]), str(row["sha256"]),  # type: ignore[arg-type]
                        str(row["generation"]), float(row["recorded_at"]), bool(row["first_run"]))  # type: ignore[arg-type]

    def get(self, identity: tuple[int, int]) -> Download | None:
        row = self.db.download(*identity)
        return self._item(row) if row else None

    def put(self, item: Download) -> None:
        self.db.put_download(item.volume, item.file_id, item.path, item.sha256, item.gate_generation,
                             item.recorded_at, item.first_run_seen)

    def delete(self, identity: tuple[int, int]) -> None:
        self.db.delete_download(*identity)

    def values(self) -> tuple[Download, ...]:
        return tuple(self._item(row) for row in self.db.downloads())


@dataclass(frozen=True)
class RescanRequest:
    identity: tuple[int, int]
    path: str
    sha256: str
    reason: str


class RescanQueue:
    def __init__(self, store: DownloadStore, *, capacity: int = 4096,
                 ttl: float = 30 * 86400, clock: Callable[[], float] = time.time) -> None:
        if capacity <= 0 or ttl <= 0:
            raise ValueError("bounds")
        self.store, self.capacity, self.ttl, self.clock = store, capacity, ttl, clock
        self.pending: dict[tuple[int, int], RescanRequest] = {}
        self.gap_counts: dict[str, int] = {}

    def _gap(self, reason: str) -> None:
        self.gap_counts[reason] = self.gap_counts.get(reason, 0) + 1

    def expire(self) -> None:
        now = self.clock()
        for item in self.store.values():
            if now - item.recorded_at >= self.ttl:
                self.store.delete(item.identity)
                self.pending.pop(item.identity, None)
                self._gap("expired_download")

    def remember(self, item: Download) -> bool:
        self.expire()
        if (item.volume < 0 or item.file_id < 0 or len(item.sha256) != 64 or
                any(ch not in "0123456789abcdef" for ch in item.sha256) or not item.gate_generation):
            return False
        prior = self.store.get(item.identity)
        if prior == item:
            return True
        if prior is None and len(self.store.values()) >= self.capacity:
            self._gap("store_limit")
            return False
        if prior is not None and prior.sha256 != item.sha256:
            self.pending.pop(item.identity, None)
        self.store.put(item)
        return True

    def _queue(self, item: Download, reason: str) -> bool:
        if item.identity in self.pending:
            return False
        if len(self.pending) >= self.capacity:
            self._gap("queue_limit")
            return False
        self.pending[item.identity] = RescanRequest(item.identity, item.path, item.sha256, reason)
        return True

    def signatures_changed(self, generation: str) -> int:
        self.expire()
        return sum(1 for item in self.store.values()
                   if item.gate_generation != generation and self._queue(item, "generation_changed"))

    def first_run(self, identity: tuple[int, int]) -> bool:
        """True the first time a remembered download is seen running."""
        item = self.store.get(identity)
        if item is None or item.first_run_seen:
            return False
        self.store.put(replace(item, first_run_seen=True))
        return True

    def pop(self) -> RescanRequest | None:
        if not self.pending:
            return None
        key = next(iter(self.pending))
        return self.pending.pop(key)
