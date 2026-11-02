"""SQLite store shared by the tray agent and the native-messaging host.

Both processes open the same file, so WAL mode and short transactions keep a
browser-spawned host from blocking on the agent (and vice versa).
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS bad_hashes (
    sha256 TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    name   TEXT,
    added  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS bad_hosts (
    host   TEXT PRIMARY KEY,   -- lower-case hostname, no port
    kind   TEXT NOT NULL,      -- malware | phishing | miner | custom
    source TEXT NOT NULL,
    added  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS bad_urls (
    url    TEXT PRIMARY KEY,   -- normalised by urlintel.normalize_url
    kind   TEXT NOT NULL,
    source TEXT NOT NULL,
    added  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS allow_hosts (
    host  TEXT PRIMARY KEY,
    added REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS allow_hashes (
    sha256 TEXT PRIMARY KEY,
    added  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS restore_exceptions (
    path   TEXT NOT NULL,      -- os.path.realpath of the restored file, normcased
    sha256 TEXT NOT NULL,
    added  REAL NOT NULL,
    PRIMARY KEY (path, sha256)
);
CREATE TABLE IF NOT EXISTS action_journal (
    qid     TEXT PRIMARY KEY,
    path    TEXT NOT NULL,
    sha256  TEXT NOT NULL,
    started REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS downloads (
    volume      INTEGER NOT NULL,
    file_id     TEXT NOT NULL,   -- 128-bit NTFS ids do not fit an INTEGER column
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    generation  TEXT NOT NULL,
    recorded_at REAL NOT NULL,
    first_run   INTEGER NOT NULL,
    PRIMARY KEY (volume, file_id)
);
CREATE TABLE IF NOT EXISTS gate_cache (
    key     TEXT PRIMARY KEY,  -- file generation + gate generation, see gate_v2/cache.py
    payload TEXT NOT NULL,     -- the decision as JSON, revalidated on every read
    expires REAL NOT NULL,
    ts      REAL NOT NULL      -- when stored, for pruning
);
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    source   TEXT NOT NULL,    -- watcher | scan | web | download | feeds | persistence | system
    level    TEXT NOT NULL,    -- info | warning | threat
    title    TEXT NOT NULL,
    detail   TEXT NOT NULL,
    data     TEXT,             -- JSON
    notified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS quarantine (
    id            TEXT PRIMARY KEY,
    original_path TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    size          INTEGER NOT NULL,
    ts            REAL NOT NULL,
    verdict       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS feeds (
    name    TEXT PRIMARY KEY,
    updated REAL,
    count   INTEGER,
    status  TEXT
);
CREATE TABLE IF NOT EXISTS popular (
    domain TEXT PRIMARY KEY    -- registrable domain from the Tranco top list
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class _Rows:
    """Already-fetched result: the subset of the Cursor API callers use."""

    def __init__(self, rows: list[sqlite3.Row], lastrowid: int | None) -> None:
        self._rows = rows
        self.lastrowid = lastrowid

    def fetchone(self) -> sqlite3.Row | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[sqlite3.Row]:
        return self._rows


# Tables worth carrying over from a damaged database, with an optional row
# filter. Feed data lives in snapshots and is simply re-downloaded; the user's
# own blocklist entries (source='user') are kept.
SALVAGE: dict[str, str] = {
    "allow_hosts": "", "allow_hashes": "", "restore_exceptions": "", "action_journal": "", "quarantine": "",
    "events": "", "meta": "",
    "bad_hosts": "WHERE source='user'", "bad_urls": "WHERE source='user'", "bad_hashes": "WHERE source='user'",
}

SCHEMA_VERSION = 4
SCAN_CACHE_MAX_ROWS = 50_000
SCAN_CACHE_MAX_AGE = 30 * 86400


class Database:
    """State database. Opening it checks integrity and repairs a damaged file,
    so every entry point (tray, CLI, browser-spawned native host) recovers."""

    def __init__(self, path: Path | None = None, *, repair: bool = True) -> None:
        self.path = path or config.db_path()
        self._lock = threading.RLock()
        self._popular: frozenset[str] | None = None
        self.repaired_from: str | None = None  # where a damaged DB was moved to, if it was
        from .indicators import Indicators

        self._conn: sqlite3.Connection | None = None  # type: ignore[assignment]
        try:
            self._conn = self._open()
            healthy = self._conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        except sqlite3.DatabaseError:
            healthy = False
        if not healthy:
            if not repair:
                raise sqlite3.DatabaseError(f"{self.path} is damaged")
            self.repaired_from = self._rebuild()
        self.indicators = Indicators(self)
        self._migrate()

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA)
        except sqlite3.DatabaseError:
            conn.close()
            raise
        return conn

    def _rebuild(self) -> str:
        """Move the damaged file aside, recreate, and copy back what can still be read."""
        salvaged: dict[str, tuple[list[str], list[tuple[Any, ...]]]] = {}
        old = self._conn
        if old is None:
            try:
                old = sqlite3.connect(self.path, isolation_level=None)
            except sqlite3.DatabaseError:
                old = None
        if old is not None:
            for t, where in SALVAGE.items():
                try:
                    cur = old.execute(f"SELECT * FROM {t} {where}")
                    salvaged[t] = ([d[0] for d in cur.description], [tuple(r) for r in cur.fetchall()])
                except sqlite3.DatabaseError:
                    continue
            old.close()
        moved = self.path.with_name(f"{self.path.name}.corrupt-{time.strftime('%Y%m%d-%H%M%S')}")
        os.replace(self.path, moved)
        for suffix in ("-wal", "-shm"):
            side = Path(str(self.path) + suffix)
            if side.exists():
                os.replace(side, Path(str(moved) + suffix))
        self._conn = self._open()
        for t, (cols, rows) in salvaged.items():
            if rows:
                marks = ",".join("?" * len(cols))
                self._conn.executemany(f"INSERT OR IGNORE INTO {t}({','.join(cols)}) VALUES({marks})", rows)
        return str(moved)

    def check_and_repair(self) -> str | None:
        """Re-check at run time (the constructor already repaired at open).
        Returns where a damaged DB was moved to, or None if healthy."""
        if not self.indicators.healthy():
            # A damaged snapshot is just dropped; the next feed update rebuilds it.
            self.set_meta("indicators_file", "")
            self.indicators.refresh()
        if self.repaired_from:
            moved, self.repaired_from = self.repaired_from, None
            return moved
        with self._lock:
            try:
                ok = self._conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
            except sqlite3.DatabaseError:
                ok = False
            if ok:
                return None
            moved = self._rebuild()
            self._popular = None
        self.indicators.refresh()
        return moved

    def _migrate(self) -> None:
        version = int(self.get_meta("schema_version", "1") or 1)
        if version >= SCHEMA_VERSION:
            return
        if version < 2:
            self._migrate_v2()
        # v4: Gate v2 decisions replaced scan_cache; old verdicts carry no
        # coverage, so nothing in that table can be reused.
        with self.transaction():
            self._exec("DROP TABLE IF EXISTS scan_cache")
            self.set_meta("schema_version", str(SCHEMA_VERSION))
        if version < 2:
            try:
                self._exec("VACUUM")  # give the space of the v1 feed rows back once
            except sqlite3.OperationalError:
                pass  # another process has the DB open; the space is reused anyway

    def _migrate_v2(self) -> None:
        # v1 kept feed rows (hundreds of thousands) and the Tranco list in this
        # database; since v2 they live in snapshot files. Legacy rows are first
        # turned into a snapshot if none is published yet, so protection never
        # drops to empty during the upgrade, and only then deleted here.
        from . import indicators
        from .feeds import FEEDS

        names = [f.name for f in FEEDS] + ["malwarebazaar", "urlhaus", "urlhaus_hosts", "tranco_top"]
        marks = ",".join("?" * len(names))
        legacy = self._exec(f"SELECT COUNT(*) AS n FROM bad_hosts WHERE source IN ({marks})", names).fetchone()["n"]
        if legacy and not self.get_meta(indicators.POINTER_KEY):
            builder = indicators.SnapshotBuilder()
            try:
                builder.add_hosts((r["host"], r["kind"], r["source"]) for r in self._exec(
                    f"SELECT host, kind, source FROM bad_hosts WHERE source IN ({marks})", names).fetchall())
                builder.add_urls((r["url"], r["kind"], r["source"]) for r in self._exec(
                    f"SELECT url, kind, source FROM bad_urls WHERE source IN ({marks})", names).fetchall())
                builder.add_hashes((r["sha256"], r["source"], r["name"]) for r in self._exec(
                    f"SELECT sha256, source, name FROM bad_hashes WHERE source IN ({marks})", names).fetchall())
                builder.set_popular(r["domain"] for r in self._exec("SELECT domain FROM popular").fetchall())
                path = builder.finish()
            except BaseException:
                builder.discard()
                raise
            indicators.publish(self, path)
        with self.transaction():
            for t in ("bad_hosts", "bad_urls", "bad_hashes"):
                self._exec(f"DELETE FROM {t} WHERE source IN ({marks})", names)
            self._exec("DELETE FROM popular")

    def close(self) -> None:
        # The snapshot handle too: on Windows an open file can't be deleted,
        # so a leaked handle would pin superseded snapshots on disk.
        self.indicators.close()
        with self._lock:
            self._conn.close()

    def _exec(self, sql: str, args: Iterable[Any] = ()) -> _Rows:
        # Rows are fetched while holding the lock: iterating a cursor after
        # another thread has reused the connection returns mixed-up results.
        with self._lock:
            cur = self._conn.execute(sql, tuple(args))
            return _Rows(cur.fetchall(), cur.lastrowid)

    def _many(self, sql: str, rows: Iterable[tuple[Any, ...]]) -> None:
        with self._lock:
            if self._conn.in_transaction:  # part of a caller's transaction()
                self._conn.executemany(sql, rows)
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.executemany(sql, rows)
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """One atomic write transaction; the lock keeps other threads of this process out of it."""
        with self._lock:
            # IMMEDIATE takes the write lock up front, so two processes queue
            # instead of both reading and then failing to upgrade.
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    # -- meta / generation -------------------------------------------------

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self._exec("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self._exec("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def generation(self) -> int:
        """Bumped whenever signatures change, so cached scan results are re-checked."""
        return int(self.get_meta("generation", "0") or 0)

    def _increment(self, key: str) -> int:
        # One statement, so two processes bumping at once can't both write the same value.
        row = self._exec(
            "INSERT INTO meta(key,value) VALUES(?, '1') ON CONFLICT(key) DO UPDATE "
            "SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) RETURNING value", (key,)).fetchone()
        return int(row["value"])

    def bump_generation(self) -> int:
        return self._increment("generation")

    # -- indicators --------------------------------------------------------
    #
    # Feed data lives in immutable snapshot files (indicators.py). The small
    # bad_* tables here hold local entries only: the user's own reports and
    # test fixtures. Lookups consult both.

    def add_hashes(self, rows: Iterable[tuple[str, str, str | None]]) -> None:
        now = time.time()
        self._many(
            "INSERT OR IGNORE INTO bad_hashes(sha256,source,name,added) VALUES(?,?,?,?)",
            ((h.lower(), src, name, now) for h, src, name in rows),
        )

    def add_hosts(self, rows: Iterable[tuple[str, str, str]]) -> None:
        now = time.time()
        self._many(
            "INSERT OR IGNORE INTO bad_hosts(host,kind,source,added) VALUES(?,?,?,?)",
            ((h.lower(), kind, src, now) for h, kind, src in rows),
        )

    def add_urls(self, rows: Iterable[tuple[str, str, str]]) -> None:
        now = time.time()
        self._many(
            "INSERT OR IGNORE INTO bad_urls(url,kind,source,added) VALUES(?,?,?,?)",
            ((u, kind, src, now) for u, kind, src in rows),
        )

    def remove_local_host(self, host: str, source: str = "user") -> bool:
        return bool(self._exec_count("DELETE FROM bad_hosts WHERE host=? AND source=?", (host.lower(), source)))

    def _exec_count(self, sql: str, args: Iterable[Any] = ()) -> int:
        with self._lock:
            return self._conn.execute(sql, tuple(args)).rowcount

    def hash_info(self, sha256: str) -> sqlite3.Row | None:
        sha256 = sha256.lower()
        return self._exec("SELECT * FROM bad_hashes WHERE sha256=?", (sha256,)).fetchone() or self.indicators.hash(sha256)

    def host_info(self, host: str) -> sqlite3.Row | None:
        host = host.lower()
        return self._exec("SELECT * FROM bad_hosts WHERE host=?", (host,)).fetchone() or self.indicators.host(host)

    def url_info(self, url: str) -> sqlite3.Row | None:
        return self._exec("SELECT * FROM bad_urls WHERE url=?", (url,)).fetchone() or self.indicators.url(url)

    def blocked_hosts(self, limit: int = 400_000) -> list[tuple[str, str]]:
        """Hosts for the browser's network rules, most specific threat kinds first.

        The browser rule engine has a capacity limit; when the feeds exceed it,
        the curated malware/phishing lists win over the broad aggregate list.
        Everything beyond the limit is still caught by per-navigation lookups.
        """
        allowed = set(self.allowed_hosts())
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        from .indicators import KIND_RANK

        local = sorted(((r["host"], r["kind"]) for r in self._exec("SELECT host, kind FROM bad_hosts").fetchall()),
                       key=lambda hk: (KIND_RANK.get(hk[1], 5), hk[0]))
        for host, kind in local + self.indicators.hosts_ranked(limit + len(allowed)):
            if host in seen or host in allowed:
                continue
            seen.add(host)
            out.append((host, kind))
            if len(out) >= limit:
                break
        return out

    def set_popular(self, domains: Iterable[str]) -> None:
        """Local additions to the never-host-block list (feeds bring Tranco in the snapshot)."""
        self._many("INSERT OR IGNORE INTO popular(domain) VALUES(?)", ((d,) for d in domains))
        self._popular = None

    def popular_domains(self) -> frozenset[str]:
        if self._popular is None:
            self._popular = frozenset(r["domain"] for r in self._exec("SELECT domain FROM popular").fetchall())
        return self._popular | self.indicators.popular()

    def counts(self) -> dict[str, int]:
        out = {}
        for t in ("bad_hashes", "bad_hosts", "bad_urls", "quarantine", "events"):
            out[t] = self._exec(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"]
        snap = self.indicators.counts()
        out["bad_hosts"] += snap["hosts"]
        out["bad_urls"] += snap["urls"]
        out["bad_hashes"] += snap["hashes"]
        return out

    # -- allow lists -------------------------------------------------------
    #
    # allow_version lets the browser extension notice changes made in the
    # dashboard and resynchronise its exemption rules.

    def allow_version(self) -> str:
        return self.get_meta("allow_version", "0") or "0"

    def _bump_allow(self) -> None:
        self._increment("allow_version")

    def allow_host(self, host: str) -> None:
        with self.transaction():
            self._exec("INSERT OR IGNORE INTO allow_hosts(host,added) VALUES(?,?)", (host.lower(), time.time()))
            self._bump_allow()

    def is_host_allowed(self, host: str) -> bool:
        return self._exec("SELECT 1 FROM allow_hosts WHERE host=?", (host.lower(),)).fetchone() is not None

    def allowed_hosts(self) -> list[str]:
        return [r["host"] for r in self._exec("SELECT host FROM allow_hosts ORDER BY host").fetchall()]

    def remove_allowed_host(self, host: str) -> None:
        with self.transaction():
            self._exec("DELETE FROM allow_hosts WHERE host=?", (host.lower(),))
            self._bump_allow()

    def allow_hash(self, sha256: str) -> None:
        self._exec("INSERT OR IGNORE INTO allow_hashes(sha256,added) VALUES(?,?)", (sha256.lower(), time.time()))

    def add_restore_exception(self, path: str, sha256: str) -> None:
        self._exec("INSERT OR IGNORE INTO restore_exceptions(path,sha256,added) VALUES(?,?,?)",
                   (os.path.normcase(os.path.realpath(path)), sha256.lower(), time.time()))

    def has_restore_exception(self, path: str, sha256: str) -> bool:
        return self._exec("SELECT 1 FROM restore_exceptions WHERE path=? AND sha256=?",
                          (os.path.normcase(os.path.realpath(path)), sha256.lower())).fetchone() is not None

    def is_hash_allowed(self, sha256: str) -> bool:
        return self._exec("SELECT 1 FROM allow_hashes WHERE sha256=?", (sha256.lower(),)).fetchone() is not None

    # -- scan cache --------------------------------------------------------

    # The gate_v2.cache.CacheStore interface. What may be stored and reused is
    # decided there; this is only storage. The cache serves on-demand scans;
    # real-time protection always re-reads changed files.

    def get(self, key: str) -> str | None:
        row = self._exec("SELECT payload FROM gate_cache WHERE key=?", (key,)).fetchone()
        return row["payload"] if row else None

    def put(self, key: str, payload: str, expires_at: float) -> None:
        self._exec(
            "INSERT INTO gate_cache(key,payload,expires,ts) VALUES(?,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET payload=excluded.payload, expires=excluded.expires, ts=excluded.ts",
            (key, payload, expires_at, time.time()))

    def prune_cache(self, max_rows: int = SCAN_CACHE_MAX_ROWS, max_age: float = SCAN_CACHE_MAX_AGE) -> int:
        """Drop expired entries and keep the newest `max_rows`; Temp churn would otherwise grow it forever."""
        n = self._exec_count("DELETE FROM gate_cache WHERE expires < ? OR ts < ?", (time.time(), time.time() - max_age))
        n += self._exec_count(
            "DELETE FROM gate_cache WHERE key NOT IN (SELECT key FROM gate_cache ORDER BY ts DESC LIMIT ?)", (max_rows,))
        return n

    # -- events ------------------------------------------------------------

    def add_event(self, source: str, level: str, title: str, detail: str, data: dict[str, Any] | None = None) -> int:
        cur = self._exec(
            "INSERT INTO events(ts,source,level,title,detail,data) VALUES(?,?,?,?,?,?)",
            (time.time(), source, level, title, detail, json.dumps(data, ensure_ascii=False) if data else None),
        )
        return int(cur.lastrowid or 0)

    def events(self, limit: int = 200, source: str | None = None) -> list[dict[str, Any]]:
        if source:
            rows = self._exec("SELECT * FROM events WHERE source=? ORDER BY id DESC LIMIT ?", (source, limit))
        else:
            rows = self._exec("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows.fetchall()]

    def take_unnotified(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = [dict(r) for r in self._conn.execute(
                "SELECT * FROM events WHERE notified=0 AND level!='info' ORDER BY id").fetchall()]
            if rows:
                self._conn.execute("UPDATE events SET notified=1 WHERE id<=?", (rows[-1]["id"],))
            return rows

    # -- quarantine --------------------------------------------------------

    def add_quarantine(self, qid: str, original: str, sha256: str, size: int, verdict: dict[str, Any]) -> None:
        self._exec(
            "INSERT INTO quarantine(id,original_path,sha256,size,ts,verdict) VALUES(?,?,?,?,?,?)",
            (qid, original, sha256, size, time.time(), json.dumps(verdict, ensure_ascii=False)),
        )

    def quarantine_items(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec("SELECT * FROM quarantine ORDER BY ts DESC").fetchall()]

    def quarantine_item(self, qid: str) -> dict[str, Any] | None:
        row = self._exec("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
        return dict(row) if row else None

    def remove_quarantine(self, qid: str) -> None:
        self._exec("DELETE FROM quarantine WHERE id=?", (qid,))

    def download(self, volume: int, file_id: int) -> dict[str, Any] | None:
        row = self._exec("SELECT * FROM downloads WHERE volume=? AND file_id=?", (volume, str(file_id))).fetchone()
        return dict(row) if row else None

    def downloads(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec("SELECT * FROM downloads").fetchall()]

    def put_download(self, volume: int, file_id: int, path: str, sha256: str, generation: str,
                     recorded_at: float, first_run: bool) -> None:
        self._exec("INSERT OR REPLACE INTO downloads(volume,file_id,path,sha256,generation,recorded_at,first_run) "
                   "VALUES(?,?,?,?,?,?,?)", (volume, str(file_id), path, sha256, generation, recorded_at, int(first_run)))

    def delete_download(self, volume: int, file_id: int) -> None:
        self._exec("DELETE FROM downloads WHERE volume=? AND file_id=?", (volume, str(file_id)))

    def open_action(self, qid: str, path: str, sha256: str) -> None:
        self._exec("INSERT INTO action_journal(qid,path,sha256,started) VALUES(?,?,?,?)",
                   (qid, path, sha256, time.time()))

    def close_action(self, qid: str) -> None:
        self._exec("DELETE FROM action_journal WHERE qid=?", (qid,))

    def open_actions(self, started_before: float) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec("SELECT * FROM action_journal WHERE started<?", (started_before,)).fetchall()]

    # -- feeds -------------------------------------------------------------

    def set_feed(self, name: str, count: int | None, status: str) -> None:
        self._exec(
            "INSERT INTO feeds(name,updated,count,status) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
            "updated=excluded.updated, count=excluded.count, status=excluded.status",
            (name, time.time(), count, status),
        )

    def feed_status(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec("SELECT * FROM feeds ORDER BY name").fetchall()]
