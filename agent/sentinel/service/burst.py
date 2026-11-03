"""Deterministic notify-only file burst scoring and bounded incident state."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from math import isfinite
from typing import Deque

MAX_CANARIES = 256
MAX_FILE_OBJECTS = 65_536
MAX_PROCESSES = 16_384
MAX_SCORES = 4_096
MAX_QUEUE = 8_192
MAX_CANDIDATES = 256
MAX_PROMPTS = 16
MAX_PATH = 260
WINDOW_SECONDS = 10.0  # R14 hypothesis; freeze before owner measurement.
BURST_DOCUMENTS = 8
BURST_DIRECTORIES = 2


class State(str, Enum):
    DISABLED = "DISABLED"
    OBSERVE = "OBSERVE"
    CANDIDATE = "CANDIDATE"
    VERIFIED = "VERIFIED"
    SUSPEND_ATTEMPTED = "SUSPEND_ATTEMPTED"
    HELD = "HELD"
    RESUMED = "RESUMED"
    GAP = "GAP/ABSTAIN"
    CLOSED = "CLOSED"


@dataclass(frozen=True)
class Operation:
    at: float
    pid: int
    creation_time: int
    path: str
    directory: str
    kind: str  # read | write | replace | rename | delete
    owner_document: bool = False
    canary: bool = False
    confirmed: bool = False
    attributed: bool = False  # Caller must have rechecked PID, creation time, and image.


@dataclass(frozen=True)
class Decision:
    state: State
    alert: bool
    reason: str
    distinct_documents: int = 0
    directories: int = 0


@dataclass
class Counters:
    accepted: int = 0
    evicted: int = 0
    truncated: int = 0
    parse_failures: int = 0
    dropped: int = 0
    unmatched_names: int = 0
    unmatched_pids: int = 0
    gaps: int = 0
    alerts: int = 0


@dataclass
class Incident:
    state: State = State.DISABLED
    gap_start: float | None = None
    gap_end: float | None = None
    gap_reason: str = ""
    reconciliation_debt: int = 0
    counters: Counters = field(default_factory=Counters)
    _history: dict[tuple[int, int], Deque[Operation]] = field(default_factory=dict)
    _history_count: int = 0
    _alerted: set[tuple[int, int]] = field(default_factory=set)

    def enable(self) -> None:
        if self.state == State.DISABLED:
            self.state = State.OBSERVE

    def open_gap(self, at: float, reason: str, debt: int = 1) -> Decision:
        if self.state != State.GAP:
            self.gap_start = at
            self.counters.gaps += 1
        self.state = State.GAP
        self.gap_reason = reason[:64]
        self.reconciliation_debt += max(0, debt)
        self._history.clear()
        self._history_count = 0
        self._alerted.clear()
        return Decision(self.state, False, self.gap_reason)

    def close_gap(self, at: float, *, resubscribed: bool, canaries_fresh: bool,
                  debt_reconciled: bool) -> bool:
        if self.state != State.GAP or not all((resubscribed, canaries_fresh, debt_reconciled)):
            return False
        self.gap_end = at
        self.reconciliation_debt = 0
        self.state = State.OBSERVE
        return True

    def forget_process(self, pid: int) -> None:
        # A later instance of the same PID must not inherit an earlier burst.
        for key in tuple(self._history):
            if key[0] == pid:
                self._history_count -= len(self._history.pop(key))
                self._alerted.discard(key)

    def observe(self, op: Operation, *, loss: bool = False, shadow: bool = False) -> Decision:
        if (not isinstance(op, Operation) or not isinstance(op.at, (int, float))
                or not isfinite(op.at) or not isinstance(op.path, str)
                or not isinstance(op.directory, str) or not isinstance(op.kind, str)
                or not isinstance(op.pid, int) or not isinstance(op.creation_time, int)):
            self.counters.parse_failures += 1
            return self.open_gap(0.0, "malformed_operation")
        if loss:
            return self.open_gap(op.at, "trace_or_queue_loss")
        if self.state == State.GAP:
            return Decision(State.GAP, False, self.gap_reason)
        if self.state != State.OBSERVE and self.state not in (State.CANDIDATE, State.VERIFIED):
            return Decision(self.state, False, "inactive")
        if len(op.path) > MAX_PATH or len(op.directory) > MAX_PATH:
            self.counters.truncated += 1
            return self.open_gap(op.at, "path_truncated")
        if not op.attributed or op.pid <= 4 or (op.creation_time <= 0 and
                                                not (shadow and op.creation_time == 0)):
            self.counters.unmatched_pids += 1
            return self.open_gap(op.at, "unattributed_process")
        if not op.path or not op.directory:
            self.counters.unmatched_names += 1
            return self.open_gap(op.at, "unattributed_file")
        if op.kind not in ("read", "write", "replace", "rename", "delete"):
            self.counters.parse_failures += 1
            return self.open_gap(op.at, "unknown_operation")
        key = (op.pid, op.creation_time)
        if key not in self._history and len(self._history) >= MAX_SCORES:
            self.counters.evicted += 1
            return self.open_gap(op.at, "score_capacity")
        history = self._history.setdefault(key, deque())
        if history and op.at < history[-1].at:
            self.counters.parse_failures += 1
            return self.open_gap(op.at, "out_of_order_event")
        while history and op.at - history[0].at > WINDOW_SECONDS:
            history.popleft()
            self._history_count -= 1
        if self._history_count >= MAX_QUEUE:
            self.counters.dropped += 1
            return self.open_gap(op.at, "score_queue_capacity")
        history.append(op)
        self._history_count += 1
        self.counters.accepted += 1
        reads: dict[str, float] = {}
        for event in history:
            if event.kind == "read":
                reads.setdefault(event.path, event.at)
        changed = {e.path: e for e in history if e.owner_document and e.kind in
                   ("write", "replace", "rename", "delete") and (e.confirmed or shadow)}
        confirmed_changed = {path for path, event in changed.items() if event.confirmed}
        read_changed = {p: e for p, e in changed.items() if p in reads and reads[p] <= e.at}
        directories = {e.directory for e in read_changed.values()}
        canaries = {e.path for e in history if e.canary and e.confirmed and e.kind in
                    ("write", "replace", "rename", "delete")}
        if key in self._alerted:
            return Decision(self.state, False, "already_alerted", len(changed), len(directories))
        if canaries:
            self.state = State.CANDIDATE
            if len(canaries) >= 2 or any(p not in canaries for p in confirmed_changed):
                self.state = State.VERIFIED
                if len(self._alerted) >= MAX_CANDIDATES:
                    self.counters.dropped += 1
                    return self.open_gap(op.at, "candidate_capacity")
                self._alerted.add(key)
                self.counters.alerts += 1
                return Decision(self.state, True, "corroborated_canary", len(changed), len(directories))
        if len(read_changed) >= BURST_DOCUMENTS and len(directories) >= BURST_DIRECTORIES:
            if len(self._alerted) >= MAX_CANDIDATES:
                self.counters.dropped += 1
                return self.open_gap(op.at, "candidate_capacity")
            self._alerted.add(key)
            self.counters.alerts += 1
            reason = "provisional_document_burst" if shadow else "document_burst"
            return Decision(self.state, True, reason, len(read_changed), len(directories))
        return Decision(self.state, False, "insufficient_evidence", len(read_changed), len(directories))

    def close(self) -> None:
        self._history.clear()
        self._history_count = 0
        self._alerted.clear()
        self.state = State.CLOSED
