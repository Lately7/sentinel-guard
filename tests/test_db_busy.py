"""A locked database is busy, not damaged: rebuilding it would move good data aside."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from sentinel import db as db_module
from sentinel.db import Database


def locked(path: Path) -> sqlite3.Connection:
    # A database not yet in WAL: turning it on needs the exclusive lock held here.
    holder = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    holder.execute("CREATE TABLE IF NOT EXISTS keep(value TEXT)")
    holder.execute("INSERT INTO keep VALUES ('precious')")
    holder.execute("BEGIN EXCLUSIVE")
    return holder


def test_a_database_another_process_holds_is_left_exactly_where_it_is(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "BUSY_MILLISECONDS", 200)
    path = tmp_path / "state.db"
    holder = locked(path)
    with pytest.raises(sqlite3.OperationalError):
        Database(path)
    holder.rollback()
    assert holder.execute("SELECT value FROM keep").fetchone() == ("precious",)
    holder.close()
    assert [p.name for p in tmp_path.iterdir() if "corrupt" in p.name] == []


def test_a_short_wait_for_the_other_process_is_only_a_wait(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "BUSY_MILLISECONDS", 5000)
    path = tmp_path / "state.db"
    holder = locked(path)
    threading.Timer(0.3, holder.rollback).start()
    opened = Database(path)
    try:
        assert opened.repaired_from is None
        assert opened._exec("SELECT value FROM keep").fetchone()[0] == "precious"
    finally:
        opened.close()
        holder.close()
    assert [p.name for p in tmp_path.iterdir() if "corrupt" in p.name] == []


def test_a_truly_damaged_file_is_still_rebuilt(tmp_path):
    path = tmp_path / "state.db"
    path.write_bytes(b"this is not a database, and never was one" * 100)
    opened = Database(path)
    try:
        assert opened.repaired_from is not None and Path(opened.repaired_from).exists()
    finally:
        opened.close()


def test_a_busy_check_at_run_time_is_not_damage(db, monkeypatch):
    class Busy:
        def execute(self, sql):
            error = sqlite3.OperationalError("database is locked")
            error.sqlite_errorcode = sqlite3.SQLITE_BUSY
            raise error

    real = db._conn
    monkeypatch.setattr(db, "_conn", Busy())
    monkeypatch.setattr(db, "_rebuild", lambda: pytest.fail("a lock is not damage"))
    monkeypatch.setattr(db.indicators, "healthy", lambda: True)
    assert db.check_and_repair() is None
    monkeypatch.setattr(db, "_conn", real)
