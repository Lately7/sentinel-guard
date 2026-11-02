"""Engine signature updates: a failure must not look like a fresh database (RT-010)."""

from __future__ import annotations

from sentinel import feeds

HOUR = 3600.0


def test_first_run_is_due(db):
    assert feeds.engine_update_due(db, "clamav", 4 * HOUR, now=1_000_000)


def test_success_waits_the_full_period(db):
    feeds.record_engine_update(db, "clamav", "ok", now=1_000_000)
    assert not feeds.engine_update_due(db, "clamav", 4 * HOUR, now=1_000_000 + 3 * HOUR)
    assert feeds.engine_update_due(db, "clamav", 4 * HOUR, now=1_000_000 + 4 * HOUR + 1)


def test_failure_is_retried_soon_not_after_the_period(db):
    feeds.record_engine_update(db, "yara", "ok: 5000 rules", now=1_000_000)
    t = 1_000_000 + 25 * HOUR
    feeds.record_engine_update(db, "yara", "error: synthetic failure", now=t)
    assert db.get_meta("yara_updated") == str(1_000_000)  # last good update is kept
    assert not feeds.engine_update_due(db, "yara", 24 * HOUR, now=t + 60)
    assert feeds.engine_update_due(db, "yara", 24 * HOUR, now=t + feeds.ENGINE_RETRY_AFTER + 1)


def test_keys_are_independent(db):
    feeds.record_engine_update(db, "clamav", "error: freshclam exit 2", now=1_000_000)
    assert feeds.engine_update_due(db, "yara", 24 * HOUR, now=1_000_000 + 1)
