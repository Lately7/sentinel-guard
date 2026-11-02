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
CREATE TABLE IF NOT EXISTS scan_cache (
    path   TEXT PRIMARY KEY,
    size   INTEGER NOT NULL,
    mtime  REAL NOT NULL,
    sha256 TEXT NOT NULL,
    label  TEXT NOT NULL,
    result TEXT NOT NULL,      -- Verdict.to_dict() as JSON
    db_gen INTEGER NOT NULL    -- signatures generation the result was computed with
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


# Tables worth carrying over from a damaged database; indicator tables are
# rebuilt by the next feed update instead.
SALVAGE_TABLES = ("allow_hosts", "allow_hashes", "quarantine", "events", "meta",
                  "bad_hosts", "bad_urls", "bad_hashes", "popular")


class Database:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or config.db_path()
        self._lock = threading.RLock()
        self._popular: frozenset[str] | None = None
        self._conn = self._open()
        from .indicators import Indicators

        self.indicators = Indicators(self)

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(SCHEMA)
        return conn

    def check_and_repair(self) -> str | None:
        """Run at agent start. Returns the path the damaged DB was moved to, or None if healthy."""
        if not self.indicators.healthy():
            # A damaged snapshot is just dropped; the next feed update rebuilds it.
            self.set_meta("indicators_file", "")
            self.indicators.refresh()
        try:
            ok = self._conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        except sqlite3.DatabaseError:
            ok = False
        if ok:
            return None
        with self._lock:
            salvaged: dict[str, tuple[list[str], list[tuple[Any, ...]]]] = {}
            for t in SALVAGE_TABLES:
                try:
                    cur = self._conn.execute(f"SELECT * FROM {t}")
                    salvaged[t] = ([d[0] for d in cur.description], [tuple(r) for r in cur.fetchall()])
                except sqlite3.DatabaseError:
                    continue
            self._conn.close()
            stamp = time.strftime("%Y%m%d-%H%M%S")
            moved = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
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
            self._popular = None
        return str(moved)

    def close(self) -> None:
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

    def bump_generation(self) -> int:
        g = self.generation() + 1
        self.set_meta("generation", str(g))
        return g

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
        self.set_meta("allow_version", str(int(self.allow_version()) + 1))

    def allow_host(self, host: str) -> None:
        self._exec("INSERT OR IGNORE INTO allow_hosts(host,added) VALUES(?,?)", (host.lower(), time.time()))
        self._bump_allow()

    def is_host_allowed(self, host: str) -> bool:
        return self._exec("SELECT 1 FROM allow_hosts WHERE host=?", (host.lower(),)).fetchone() is not None

    def allowed_hosts(self) -> list[str]:
        return [r["host"] for r in self._exec("SELECT host FROM allow_hosts ORDER BY host").fetchall()]

    def remove_allowed_host(self, host: str) -> None:
        self._exec("DELETE FROM allow_hosts WHERE host=?", (host.lower(),))
        self._bump_allow()

    def allow_hash(self, sha256: str) -> None:
        self._exec("INSERT OR IGNORE INTO allow_hashes(sha256,added) VALUES(?,?)", (sha256.lower(), time.time()))

    def is_hash_allowed(self, sha256: str) -> bool:
        return self._exec("SELECT 1 FROM allow_hashes WHERE sha256=?", (sha256.lower(),)).fetchone() is not None

    # -- scan cache --------------------------------------------------------

    def cached_result(self, path: str, size: int, mtime: float) -> dict[str, Any] | None:
        row = self._exec("SELECT * FROM scan_cache WHERE path=?", (path,)).fetchone()
        if not row or row["size"] != size or abs(row["mtime"] - mtime) > 1e-3 or row["db_gen"] != self.generation():
            return None
        return json.loads(row["result"])

    def store_result(self, path: str, size: int, mtime: float, result: dict[str, Any]) -> None:
        self._exec(
            "INSERT INTO scan_cache(path,size,mtime,sha256,label,result,db_gen) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET size=excluded.size, mtime=excluded.mtime, sha256=excluded.sha256, "
            "label=excluded.label, result=excluded.result, db_gen=excluded.db_gen",
            (path, size, mtime, result["sha256"], result["label"], json.dumps(result), self.generation()),
        )

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

    # -- feeds -------------------------------------------------------------

    def set_feed(self, name: str, count: int | None, status: str) -> None:
        self._exec(
            "INSERT INTO feeds(name,updated,count,status) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
            "updated=excluded.updated, count=excluded.count, status=excluded.status",
            (name, time.time(), count, status),
        )

    def feed_status(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._exec("SELECT * FROM feeds ORDER BY name").fetchall()]
