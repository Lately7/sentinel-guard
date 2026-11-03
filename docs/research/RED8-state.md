# RED8 — Database and state files

All tests use `tmp_path` and the autouse `SENTINEL_HOME` fixture. They were **not run** in this sandbox, as required by the round brief. Each result below is inferred from the cited code and has an unrun regression test for Claude to execute. The installed service tree is protected by `service/installer.py:21,793-806` and checked before startup by `service/integrity.py:91-120`; medium-integrity tampering claims below apply to the per-user tray/native-host state, not to that protected tree.

## High — Disk full misclassified as database corruption

**Test:** `test_disk_full_during_open_keeps_original_database`.

**Attacker model / steps:** Full disk at the worst moment. Start with a healthy `sentinel.db`, then have `_open()` raise `SQLITE_FULL` while `Database()` initializes. The test injects that SQLite error without filling a real disk.

**Effect:** `Database.__init__` treats every non-busy `sqlite3.DatabaseError` as damage (`db.py:180-192`), then `_rebuild()` moves the healthy database to a timestamped `.corrupt-*` name (`db.py:216-239`). The second open fails while the disk is still full. On a later start, a fresh database can be created at the original path, losing active state until manual recovery. `service/backend.py:760-770` constructs this database before the service starts; `service/entry.py:29-33` does not recover an exception from its backend factory.

**Fix:** Distinguish `SQLITE_FULL`, `SQLITE_IOERR`, `SQLITE_CANTOPEN`, and permission errors from corruption. Keep the original file and retry or report degraded startup; only rebuild after an actual failed integrity check or a corruption-specific SQLite code. **Evidence:** inferred from code; test pending.

## High — Missing indicator snapshot is accepted as healthy

**Test:** `test_missing_published_snapshot_forces_feed_refresh`.

**Attacker model / steps:** An ordinary process removes the per-user published `indicators-*.db` after publication, or a power loss leaves the pointer but loses the file. The test publishes one harmless host, closes the snapshot handle, deletes the file, and checks update scheduling.

**Effect:** `Indicators._current()` opens only when the target is a file, otherwise returns `None` (`indicators.py:134-155`). `healthy()` returns `True` for that `None` even when the pointer still names a file (`indicators.py:243-250`). `Database.check_and_repair()` therefore leaves the pointer alone (`db.py:248-267`). `feeds.is_due()` honors the recent attempt timestamp and returns false (`feeds.py:230-237`), while indicator lookups return no result (`indicators.py:172-193`). Browser threat indicators can disappear until the normal retry window or a manual refresh.

**Fix:** Distinguish “no snapshot ever published” from “published snapshot missing or unreadable”; clear or mark the stale pointer and force an immediate update, with a visible degraded status. **Evidence:** inferred from code; test pending.

## Medium — Interrupted settings write drops custom watch roots

**Test:** `test_interrupted_settings_save_keeps_previous_settings`.

**Attacker model / steps:** Power loss or disk full after `settings.json` is truncated and before the new JSON finishes. The test simulates a partial write to the temporary user home.

**Effect:** `Settings.save()` overwrites the live file directly (`config.py:139-140`); `Settings.load()` silently substitutes defaults for truncated JSON (`config.py:115-120`). The tray loads those settings and uses their `watch_dirs` for the file watcher (`tray.py:69-83,103-106`; `watcher.py:404-419`). A custom watch root is no longer watched, with no indication that the settings file was lost.

**Fix:** Write and flush a temporary file in the same directory, then atomically replace the old file; preserve the old version on failure and surface a recovery warning. **Evidence:** inferred from code; test pending.

## Medium — Malformed schema version aborts per-user startup

**Test:** `test_invalid_schema_version_does_not_abort_database_open`.

**Attacker model / steps:** An ordinary process changes the `meta.schema_version` value in the user-writable database to nonnumeric text. The test closes and reopens that database through the normal constructor.

**Effect:** SQLite `quick_check` still passes, but `_migrate()` calls `int()` without handling `ValueError` (`db.py:180-194,270-281`). The tray and browser native host construct `Database()` on startup (`tray.py:69-73`; `nativehost.py:292`) and can fail repeatedly. The protected service database is outside this ordinary-user tampering path.

**Fix:** Validate metadata before conversion; recover or reject the invalid row with an explicit degraded-state event while keeping the process alive. **Evidence:** inferred from code; test pending.

## Medium — Backward clock postpones threat-data updates

**Test:** `test_backward_clock_does_not_defer_updates`.

**Attacker model / steps:** The wall clock moves backwards after a successful or attempted update. The test stores timestamps in the future relative to `now`.

**Effect:** Both `feeds.is_due()` and `engine_update_due()` subtract the persisted wall-clock timestamps and treat negative elapsed time as “not due” (`feeds.py:33-38,230-237`). The tray scheduler and service maintenance rely on those predicates (`tray.py:220-230,243-255`; `service/backend.py:255-272`). Updates can stop until the clock catches up, including YARA and feed refreshes.

**Fix:** Treat timestamps later than the current wall clock as stale and eligible for retry, with a bounded retry policy. **Evidence:** inferred from code; test pending.

## Medium — Malformed feed timestamp blocks scheduled updates

**Test:** `test_malformed_feed_timestamp_does_not_stop_scheduler`.

**Attacker model / steps:** An ordinary process writes nonnumeric text to `meta.feeds_attempted` in the per-user database.

**Effect:** `feeds.is_due()` converts it with unguarded `float()` (`feeds.py:230-234`). The tray scheduler catches the exception outside its update call and waits another 600 seconds (`tray.py:220-230`); it repeats indefinitely until the row is repaired. The service catches an analogous exception in maintenance and skips subsequent work in that iteration (`service/backend.py:255-272`), though the installed service row is ACL-protected from this attacker.

**Fix:** Parse persisted timestamps defensively, treat invalid values as absent, and record a warning. **Evidence:** inferred from code; test pending.

## Low — Backward clock delays crash-action reconciliation

**Test:** `test_backward_clock_reconciles_future_dated_action`.

**Attacker model / steps:** A crash interrupts quarantine after the action journal is written; the clock then moves backwards. The test leaves a harmless future-dated action in the temporary database.

**Effect:** `quarantine.reconcile()` requests only rows older than `time.time() - grace` (`quarantine.py:258-263`), while `Database.open_actions()` filters with `started < ?` (`db.py:666-674`). The stranded row and any related quarantine blob wait until the old wall-clock time passes. Reconciliation is called at tray and service start (`tray.py:69-78`; `service/backend.py:221-225`).

**Fix:** Regard a journal timestamp later than current time as interrupted too, after coordinating with any live action, or use monotonic process-local age only for the grace decision. **Evidence:** inferred from code; test pending.

## Other requested probes

The installed state directory and its children are checked for reparse points and ACLs before service startup (`service/integrity.py:91-106`; `service/installer.py:793-806`), so a preexisting ordinary-user junction is rejected. SQLite uses WAL, a 30-second busy timeout and `BEGIN IMMEDIATE` for transactions (`db.py:196-214,332-357`); concurrent opening and lock failures are differentiated from corruption (`db.py:161-164,183-187`). These paths can delay or fail startup under a persistent lock, but this review found no separate ordinary-user path to hold a lock on the protected service database. Truncation of the per-user SQLite file is handled by the quick-check/rebuild path (`db.py:180-246`), with the expected limitation that unreadable rows cannot be salvaged. No additional finding is asserted for those probes.
