"""Threat-indicator snapshots, rebuilt from scratch on every feed update.

Hundreds of thousands of feed rows used to be deleted and re-inserted in place
inside the shared state database; twice that churn left the database damaged.
Now each update writes a brand-new file, and readers switch to it once a
pointer in the state DB says it is published. A published file is never
written again, so readers open it `immutable` (no locks, no journal) and a
damaged snapshot costs nothing but a re-download.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from . import config

if TYPE_CHECKING:
    from .db import Database

log = logging.getLogger(__name__)

KIND_RANK = {"malware": 0, "phishing": 1, "scam": 2, "miner": 3, "pup": 4}

SNAPSHOT_SCHEMA = """
-- One row per (host, feed): a host listed by two feeds keeps both rows, so a
-- failed feed's carry-over still has its own copy after the other delists it.
CREATE TABLE hosts  (host TEXT NOT NULL, kind TEXT NOT NULL, source TEXT NOT NULL, rank INTEGER NOT NULL,
                     PRIMARY KEY (host, source)) WITHOUT ROWID;
CREATE TABLE urls   (url TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE hashes (sha256 TEXT PRIMARY KEY, source TEXT NOT NULL, name TEXT) WITHOUT ROWID;
CREATE TABLE popular (domain TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE info (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
"""

POINTER_KEY = "indicators_file"
RECHECK_SECONDS = 5.0


def snapshot_dir() -> Path:
    d = config.data_dir() / "indicators"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _open_ro(path: Path) -> sqlite3.Connection:
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


class SnapshotBuilder:
    """Writes one new snapshot file. Nothing reads it until `publish()`."""

    def __init__(self, directory: Path | None = None) -> None:
        d = directory or snapshot_dir()
        self.path = d / f"indicators-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}.db"
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=OFF")  # a failed build is simply discarded
        self._conn.execute("PRAGMA synchronous=OFF")
        self._conn.executescript(SNAPSHOT_SCHEMA)
        self._conn.execute("BEGIN")
        self.counts = {"hosts": 0, "urls": 0, "hashes": 0, "popular": 0}

    def add_hosts(self, rows: Iterable[tuple[str, str, str]]) -> int:
        cur = self._conn.executemany(
            "INSERT OR IGNORE INTO hosts(host,kind,source,rank) VALUES(?,?,?,?)",
            ((h.lower(), k, s, KIND_RANK.get(k, 5)) for h, k, s in rows))
        self.counts["hosts"] += max(cur.rowcount, 0)
        return cur.rowcount

    def add_urls(self, rows: Iterable[tuple[str, str, str]]) -> int:
        cur = self._conn.executemany("INSERT OR IGNORE INTO urls(url,kind,source) VALUES(?,?,?)", rows)
        self.counts["urls"] += max(cur.rowcount, 0)
        return cur.rowcount

    def add_hashes(self, rows: Iterable[tuple[str, str, str | None]]) -> int:
        cur = self._conn.executemany("INSERT OR IGNORE INTO hashes(sha256,source,name) VALUES(?,?,?)",
                                     ((h.lower(), s, n) for h, s, n in rows))
        self.counts["hashes"] += max(cur.rowcount, 0)
        return cur.rowcount

    def set_popular(self, domains: Iterable[str]) -> None:
        cur = self._conn.executemany("INSERT OR IGNORE INTO popular(domain) VALUES(?)", ((d,) for d in domains))
        self.counts["popular"] += max(cur.rowcount, 0)

    def finish(self) -> Path:
        self.counts["hosts"] = self._conn.execute("SELECT COUNT(DISTINCT host) FROM hosts").fetchone()[0]
        for k, v in self.counts.items():
            self._conn.execute("INSERT OR REPLACE INTO info(key,value) VALUES(?,?)", (f"count_{k}", str(v)))
        self._conn.execute("INSERT OR REPLACE INTO info(key,value) VALUES('built',?)", (str(time.time()),))
        # Distinct hosts with their highest-priority kind, precomputed once so
        # readers never aggregate over the per-feed rows.
        self._conn.execute("CREATE TABLE best (host TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL, "
                           "rank INTEGER NOT NULL) WITHOUT ROWID")
        self._conn.execute("INSERT INTO best SELECT host, kind, source, MIN(rank) FROM hosts GROUP BY host")
        self._conn.execute("CREATE INDEX best_rank ON best(rank, host)")
        self._conn.execute("COMMIT")
        ok = self._conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        self._conn.close()
        if not ok:
            self.discard()
            raise sqlite3.DatabaseError("new indicator snapshot failed its integrity check")
        return self.path

    def discard(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
        self.path.unlink(missing_ok=True)


class Indicators:
    """Read side: follows the published pointer and reopens when it changes."""

    def __init__(self, state: "Database") -> None:
        self._state = state
        self._lock = threading.Lock()
        self._path: str | None = None
        self._conn: sqlite3.Connection | None = None
        self._checked = 0.0
        self._popular: frozenset[str] | None = None
        self._best = "best"

    def _current(self) -> sqlite3.Connection | None:
        with self._lock:
            now = time.monotonic()
            if self._conn is not None and now - self._checked < RECHECK_SECONDS:
                return self._conn
            self._checked = now
            target = self._state.get_meta(POINTER_KEY)
            if target != self._path:
                if self._conn is not None:
                    self._conn.close()
                self._conn, self._path, self._popular = None, target, None
                if target and Path(target).is_file():
                    try:
                        self._conn = _open_ro(Path(target))
                        tables = {r[0] for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                        # Format 1 snapshots (before the per-feed rows) have no
                        # `best` table; their `hosts` table already holds one row per host.
                        self._best = "best" if "best" in tables else "hosts"
                    except sqlite3.Error as e:
                        log.warning("cannot open indicator snapshot %s: %s", target, e)
                        self._conn = None
            return self._conn

    @property
    def outdated(self) -> bool:
        """True while serving a snapshot in an older format; the next feed update replaces it."""
        return self._current() is not None and self._best != "best"

    def refresh(self) -> None:
        with self._lock:
            self._checked = 0.0

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
            self._conn, self._path, self._popular = None, None, None

    def _one(self, sql: str, args: tuple) -> sqlite3.Row | None:
        conn = self._current()
        if conn is None:
            return None
        try:
            with self._lock:
                return conn.execute(sql, args).fetchone()
        except sqlite3.DatabaseError as e:
            # Never silently: an unreadable snapshot means no protection.
            log.warning("indicator lookup failed: %s", e)
            return None

    def host(self, host: str) -> sqlite3.Row | None:
        if self._current() is None:
            return None
        return self._one(f"SELECT host, kind, source FROM {self._best} WHERE host=? ORDER BY rank LIMIT 1", (host,))

    def url(self, url: str) -> sqlite3.Row | None:
        return self._one("SELECT url, kind, source FROM urls WHERE url=?", (url,))

    def hash(self, sha256: str) -> sqlite3.Row | None:
        return self._one("SELECT sha256, source, name FROM hashes WHERE sha256=?", (sha256,))

    def hosts_ranked(self, limit: int) -> list[tuple[str, str]]:
        conn = self._current()
        if conn is None:
            return []
        try:
            with self._lock:
                rows = conn.execute(f"SELECT host, kind FROM {self._best} ORDER BY rank, host LIMIT ?", (limit,)).fetchall()
            return [(r["host"], r["kind"]) for r in rows]
        except sqlite3.DatabaseError as e:
            log.warning("indicator listing failed: %s", e)
            return []

    def rows_for_source(self, table: str, source: str) -> list[tuple]:
        """Previous rows of one feed, carried into the next snapshot when that feed fails to download."""
        if table not in ("hosts", "urls", "hashes"):
            raise ValueError(table)
        conn = self._current()
        if conn is None:
            return []
        cols = {"hosts": "host, kind, source", "urls": "url, kind, source", "hashes": "sha256, source, name"}[table]
        try:
            with self._lock:
                return [tuple(r) for r in conn.execute(f"SELECT {cols} FROM {table} WHERE source=?", (source,))]
        except sqlite3.DatabaseError:
            return []

    def popular(self) -> frozenset[str]:
        if self._current() is None:
            return frozenset()
        if self._popular is None:
            try:
                with self._lock:
                    self._popular = frozenset(r[0] for r in self._conn.execute("SELECT domain FROM popular"))  # type: ignore[union-attr]
            except sqlite3.DatabaseError:
                return frozenset()
        return self._popular

    def counts(self) -> dict[str, int]:
        conn = self._current()
        if conn is None:
            return {"hosts": 0, "urls": 0, "hashes": 0}
        try:
            with self._lock:
                info = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM info")}
            return {k: int(info.get(f"count_{k}", 0)) for k in ("hosts", "urls", "hashes")}
        except sqlite3.DatabaseError:
            return {"hosts": 0, "urls": 0, "hashes": 0}

    def healthy(self) -> bool:
        conn = self._current()
        if conn is None:
            return True  # nothing published yet is not damage
        try:
            with self._lock:
                return conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        except sqlite3.DatabaseError:
            return False


def publish(state: "Database", path: Path) -> None:
    # Pointer and versions change together: a crash in between must not leave
    # URL lookups on new data while the browser keeps rules for the old.
    with state.transaction():
        state.set_meta(POINTER_KEY, str(path))
        state.set_meta("blocklist_version", str(state.bump_generation()))
    state.indicators.refresh()
    state.indicators.counts()  # switch this process to the new file now, releasing the old one
    cleanup(keep={str(path)})


def cleanup(keep: set[str]) -> None:
    """Delete superseded snapshots. Files still open in another process (a
    browser's native host) can't be deleted on Windows; they go next time."""
    for p in snapshot_dir().glob("indicators-*.db"):
        if str(p) in keep:
            continue
        try:
            os.remove(p)
        except OSError:
            pass
