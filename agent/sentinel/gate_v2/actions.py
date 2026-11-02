"""The action boundary (R11 §4, invariant 11).

Whether an automatic action may still run. Turning protection off revokes the
current generation first and then waits for what already started, so "off" is
only ever published once nothing can act any more.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager


class ProtectionStopped(Exception):
    pass


class ProtectionBarrier:
    def __init__(self) -> None:
        self._changed = threading.Condition()
        self._generation = 1
        self._revoked = False
        self._running = 0

    def current(self) -> int | None:
        """The generation an action may run under; None while protection is off."""
        with self._changed:
            return None if self._revoked else self._generation

    def stamp(self) -> int:
        """The generation a scan starting now belongs to, even while protection is off."""
        with self._changed:
            return self._generation

    @contextmanager
    def action(self, generation: int | None = None) -> Iterator[None]:
        with self._changed:
            if self._revoked or (generation is not None and generation != self._generation):
                raise ProtectionStopped
            self._running += 1
        try:
            yield
        finally:
            with self._changed:
                self._running -= 1
                self._changed.notify_all()

    def revoke(self, timeout: float) -> bool:
        """Stops later actions and waits for running ones; False if one is still running."""
        deadline = time.monotonic() + timeout
        with self._changed:
            self._revoked = True
            self._generation += 1
            while self._running:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._changed.wait(remaining)
            return True

    def resume(self) -> int:
        with self._changed:
            self._revoked = False
            return self._generation
