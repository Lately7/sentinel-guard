from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

FEED_WORKER = textwrap.dedent("""
    import sys, time
    sys.path.insert(0, sys.argv[1])
    from sentinel import feeds
    from sentinel.db import Database
    hosts = "\\n".join(f"h{i}-{sys.argv[2]}.example" for i in range(30000))
    feed = feeds.Feed("big", "u", "bad_hosts", "phishing", feeds.parse_hosts)
    db = Database()
    for _ in range(3):
        res = feeds.update_all(db, [feed], fetcher=lambda u: hosts)
        print(res, flush=True)
""")


def test_concurrent_feed_updates_do_not_corrupt(sentinel_home, tmp_path):
    script = tmp_path / "worker.py"
    script.write_text(FEED_WORKER)
    env = {**os.environ, "SENTINEL_HOME": str(sentinel_home)}
    procs = [subprocess.Popen([sys.executable, str(script), str(ROOT / "agent"), tag], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
             for tag in ("a", "b")]
    outs = [p.communicate(timeout=180) for p in procs]
    for p, (out, err) in zip(procs, outs):
        assert p.returncode == 0, err
    conn = sqlite3.connect(sentinel_home / "sentinel.db")
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    from sentinel.db import Database

    db = Database()
    assert db.counts()["bad_hosts"] == 30000  # exactly one worker's list, never a mix or a partial import
    tag = "a" if db.host_info("h0-a.example") else "b"
    assert db.host_info(f"h29999-{tag}.example") is not None


def test_damaged_database_is_rebuilt_with_salvage(sentinel_home):
    from sentinel.db import Database

    db = Database()
    db.allow_host("trusted.example")
    db.add_hosts((f"x{i}.example", "malware", "f") for i in range(50000))
    db.add_event("system", "info", "kept", "event survives")
    db.close()
    p = sentinel_home / "sentinel.db"
    # Force everything into the main file, then overwrite pages in the middle.
    c = sqlite3.connect(p)
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    c.close()
    data = bytearray(p.read_bytes())
    mid = len(data) // 2
    data[mid:mid + 40960] = os.urandom(40960)
    p.write_bytes(bytes(data))

    db = Database()
    moved = db.check_and_repair()
    assert moved and Path(moved).exists()
    assert db.check_and_repair() is None  # healthy now
    assert db.is_host_allowed("trusted.example")
    assert any(e["title"] == "kept" for e in db.events(10))


def test_feeds_due_only_counts_successful_updates(db):
    from sentinel import feeds

    assert feeds.is_due(db, 6)
    db.set_feed("a", None, "error: offline")
    assert feeds.is_due(db, 6)
    db.set_feed("b", 10, "ok")
    assert not feeds.is_due(db, 6)
    assert feeds.is_due(db, 6, now=time.time() + 7 * 3600)


@pytest.mark.skipif(os.name != "nt", reason="named kernel objects are Windows-only")
def test_single_instance_lock_across_processes():
    from sentinel.singleton import NamedLock

    name = f"Local\\SentinelGuard.Test.{os.getpid()}"
    held = NamedLock(name)
    assert held.acquire()
    try:
        code = f"import sys; sys.path.insert(0, {str(ROOT / 'agent')!r}); from sentinel.singleton import NamedLock; print(NamedLock({name!r}).acquire())"
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, shell=False).stdout.strip()
        assert out == "False"
    finally:
        held.release()
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, shell=False).stdout.strip()
    assert out == "True"
