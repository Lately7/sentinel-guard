"""Bounded, restartable offers after a journal coverage gap."""

from __future__ import annotations

import json
import ntpath
import os
import stat
import time
from collections import Counter
from collections.abc import Callable, Generator, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ..gate_v2 import scope, winfile
from ..gate_v2.identity import RECALL_ATTRIBUTES
from .observers import RISKY_SUFFIXES


@dataclass
class _Frame:
    path: str
    last: str = ""
    entries: Generator[os.DirEntry[str], None, None] | None = None


class _ReparseDirectory(Exception):
    pass


def _cursor_path(path: str) -> str:
    if path.startswith("\\\\?\\"):
        path = path[4:]
    return ntpath.normcase(ntpath.normpath(path))


class Reconciler:
    """Offer smart targets, then stream fixed drives in bounded passes.

    ``get`` and ``set`` store one small JSON cursor. The caller should invoke
    ``restart`` on each new journal loss, including a loss during a current walk.
    """

    def __init__(self, submit: Callable[[str, str], bool], get: Callable[[], str | None],
                 set: Callable[[str], None], *, data_root: str,
                 smart_sources: Mapping[str, scope.Source] | None = None,
                 drives: Iterable[str] | None = None, clock: Callable[[], float] = time.monotonic,
                 max_seconds: float = 60.0, max_offers: int = 1000, max_entries: int = 10000,
                 max_depth: int = 64, save_every: int = 64) -> None:
        if min(max_seconds, max_offers, max_entries, max_depth, save_every) <= 0:
            raise ValueError("bounds")
        self.submit, self.get, self.set = submit, get, set
        self.data_root = ntpath.normcase(ntpath.normpath(data_root)) if data_root else ""
        self.smart_sources = smart_sources
        self.drives = tuple(drives) if drives is not None else tuple(scope.fixed_drives())
        self.clock, self.max_seconds, self.max_offers = clock, max_seconds, max_offers
        self.max_entries, self.max_depth, self.save_every = max_entries, max_depth, save_every
        self.counts: Counter[str] = Counter()
        self._dirty = 0
        self._stack: list[_Frame] = []
        self._state = self._load()
        self._data_identity: tuple[int, int] | None = None
        if data_root:
            try:
                info = os.stat(data_root)
                self._data_identity = (info.st_dev, info.st_ino)
            except OSError:
                self.counts["identity_error"] += 1

    def _load(self) -> dict[str, Any]:
        raw = self.get()
        if raw:
            try:
                value = json.loads(raw)
                stack = value.get("stack")
                if (value.get("v") == 1 and value.get("phase") in ("smart", "deep", "done")
                        and type(value.get("drive")) is int and 0 <= value["drive"] <= len(self.drives)
                        and isinstance(value.get("smart_cursor"), (str, type(None)))
                        and isinstance(stack, list) and len(stack) <= self.max_depth
                        and all(isinstance(pair, list) and len(pair) == 2
                                and all(isinstance(part, str) for part in pair) for pair in stack)
                        and (not stack or (value["drive"] < len(self.drives)
                                           and _cursor_path(stack[0][0]) == _cursor_path(self.drives[value["drive"]])
                                           and all(_cursor_path(child[0]).startswith(
                                               _cursor_path(parent[0]).rstrip("\\") + "\\")
                                               for parent, child in zip(stack, stack[1:]))))):
                    return value
            except (ValueError, TypeError, AttributeError):
                pass
            self.counts["cursor_lost"] += 1
        return {"v": 1, "phase": "smart", "smart_cursor": None, "drive": 0, "stack": []}

    def _save(self) -> None:
        self._state["stack"] = [[frame.path, frame.last] for frame in self._stack]
        self.set(json.dumps(self._state, separators=(",", ":")))
        self._dirty = 0

    def _checkpoint(self) -> None:
        self._dirty += 1
        if self._dirty >= self.save_every:
            self._save()

    def restart(self) -> None:
        self._close_stack()
        self._state = {"v": 1, "phase": "smart", "smart_cursor": None, "drive": 0, "stack": []}
        self._save()

    def _close_stack(self) -> None:
        for frame in self._stack:
            if frame.entries is not None:
                frame.entries.close()
        self._stack.clear()

    def _wanted(self, path: str) -> bool:
        name = ntpath.normcase(ntpath.normpath(path))
        if ntpath.splitext(name)[1] not in RISKY_SUFFIXES:
            return False
        if self.data_root and (name == self.data_root or name.startswith(self.data_root + "\\")):
            return False
        return not winfile.is_protected(path)

    def _smart(self, deadline: float, offers: int) -> tuple[bool, int]:
        sources = self.smart_sources if self.smart_sources is not None else scope.windows_sources("smart", [])
        found = scope.discover("smart", sources, data_root=self.data_root or None,
                               cursor=self._state["smart_cursor"], max_seconds=max(0.001, deadline - self.clock()),
                               max_entries=self.max_entries, clock=self.clock)
        cursor = self._state["smart_cursor"]
        stopped_on_target = False
        try:
            for target in found:
                if self.clock() >= deadline or offers >= self.max_offers:
                    stopped_on_target = True
                    return False, offers
                if self._wanted(target.path):
                    stopped_on_target = True
                    if not self.submit(target.path, "reconcile"):
                        self.counts["refused"] += 1
                        return False, offers
                    stopped_on_target = False
                    self.counts["offered"] += 1
                    offers += 1
                cursor = found.report.cursor
                self._state["smart_cursor"] = cursor
                self._checkpoint()
        finally:
            found._iterator.close()
            if not stopped_on_target:
                self._state["smart_cursor"] = found.report.cursor
            for reason, count in found.report.reasons.items():
                if reason not in scope.NOT_A_GAP and reason not in ("time_limit", "entry_limit"):
                    self.counts[reason] += count
            self._save()
        if found.report.reasons["time_limit"] or found.report.reasons["entry_limit"]:
            return False, offers
        self._state["phase"] = "deep"
        self._state["smart_cursor"] = None
        self._save()
        return True, offers

    def _open(self, frame: _Frame) -> None:
        def entries() -> Generator[os.DirEntry[str], None, None]:
            path = scope._reachable(frame.path)
            with os.scandir(path) as scan:
                # A saved frame or a directory swapped after listing can now be a junction.
                info = os.stat(path, follow_symlinks=False)
                if (stat.S_ISLNK(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                    raise _ReparseDirectory
                yield from scan

        frame.entries = entries()
        if frame.last:
            for item in frame.entries:
                if item.name == frame.last:
                    return
            frame.entries.close()
            self.counts["cursor_lost"] += 1
            frame.last = ""
            frame.entries = entries()

    def _deep(self, deadline: float, offers: int) -> bool:
        if self._state["stack"] and not self._stack:
            self._stack = [_Frame(path, last) for path, last in self._state["stack"]]
        entries = 0
        while self.clock() < deadline and offers < self.max_offers and entries < self.max_entries:
            if not self._stack:
                drive = self._state["drive"]
                if drive >= len(self.drives):
                    self._state["phase"] = "done"
                    self._save()
                    return True
                self._stack.append(_Frame(self.drives[drive]))
                self._checkpoint()
            frame = self._stack[-1]
            try:
                if frame.entries is None:
                    self._open(frame)
                assert frame.entries is not None
                item = next(frame.entries)
            except StopIteration:
                frame.entries = None
                self._stack.pop()
                if not self._stack:
                    self._state["drive"] += 1
                self._checkpoint()
                continue
            except _ReparseDirectory:
                self.counts["reparse_skipped"] += 1
                frame.entries = None
                self._stack.pop()
                if not self._stack:
                    self._state["drive"] += 1
                self._checkpoint()
                continue
            except PermissionError:
                self.counts["access_denied"] += 1
                self._stack.pop()
                if not self._stack:
                    self._state["drive"] += 1
                self._checkpoint()
                continue
            except (OSError, ValueError):
                self.counts["source_error"] += 1
                self._stack.pop()
                if not self._stack:
                    self._state["drive"] += 1
                self._checkpoint()
                continue
            entries += 1
            path = item.path
            offer = False
            try:
                info = item.stat(follow_symlinks=False)
                flags = getattr(info, "st_file_attributes", 0)
                if flags & RECALL_ATTRIBUTES:
                    self.counts["cloud_placeholder"] += 1
                elif item.is_symlink() or flags & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    self.counts["reparse_skipped"] += 1
                elif stat.S_ISDIR(info.st_mode):
                    if (info.st_dev, info.st_ino) == self._data_identity or self._inside_data(path):
                        pass
                    elif len(self._stack) >= self.max_depth:
                        self.counts["depth_limit"] += 1
                    else:
                        frame.last = item.name
                        self._stack.append(_Frame(path))
                        self._checkpoint()
                        continue
                elif stat.S_ISREG(info.st_mode):
                    offer = self._wanted(path)
            except PermissionError:
                self.counts["access_denied"] += 1
            except (OSError, ValueError):
                self.counts["source_error"] += 1
            if offer:
                try:
                    accepted = self.submit(path, "reconcile")
                except Exception:
                    frame.entries.close()
                    frame.entries = None
                    self._save()
                    raise
                if not accepted:
                    self.counts["refused"] += 1
                    frame.entries.close()
                    frame.entries = None
                    self._save()
                    return False
                self.counts["offered"] += 1
                offers += 1
            frame.last = item.name
            self._checkpoint()
        self._save()
        return False

    def _inside_data(self, path: str) -> bool:
        name = ntpath.normcase(ntpath.normpath(path))
        return bool(self.data_root and (name == self.data_root or name.startswith(self.data_root + "\\")))

    def __call__(self) -> bool:
        # Observers calls only while something is owed, so a finished walk seen here is
        # a new debt, and answering "done" would clear it with nothing looked at.
        if self._state["phase"] == "done":
            self.restart()
        if self.data_root and self._data_identity is None:
            return False
        deadline = self.clock() + self.max_seconds
        offers = 0
        if self._state["phase"] == "smart":
            finished, offers = self._smart(deadline, offers)
            if not finished:
                return False
        return self._deep(deadline, offers)

    def report(self) -> dict[str, Any]:
        gaps = {reason: count for reason, count in self.counts.items()
                if reason not in ("offered", "refused")}
        finished = self._state["phase"] == "done"
        return {"phase": self._state["phase"], "finished": finished, "complete": finished and not gaps,
                "offered": self.counts["offered"], "refused": self.counts["refused"],
                "gaps": gaps}
