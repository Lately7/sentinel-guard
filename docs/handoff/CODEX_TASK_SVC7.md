# Codex task SVC7: the service looks after itself

## Allowed paths

Changed: `agent/sentinel/service/backend.py`, `agent/sentinel/service/workerclient.py`, `agent/sentinel/db.py`.
New: `tests/test_svc7.py`. Everything else is read-only.

## Findings

**1. Nothing brings a worker back on a quiet machine.** After a failed start, `last_failure` clears only
when some scan tries again. On a quiet machine nothing does, so `_retry_due` stays paused and owed files
wait. Add `Isolation.probe()`: when a failure is set and the 60 s wait has passed, attempt one start, with
no file. Call it from `_watch` at most once a minute. It must not run while a scan is in the worker, must
take the session's lock without waiting, and must never hold `_watch` past one start's deadline for long:
run it on a daemon thread with a guard so that only one runs at a time. A success clears the failure, and
the existing catch-up then runs.

**2. Every feed publish rescans every remembered download.** `backend.py:284`: `scanner.gate_id()` changes
with each publish, even when no file-scan input did, and each change can queue up to 4,096 downloads on the
one observed lane. Read how `gate_id` is built. Rescan only when the rules or hash lists that decide a file
changed, and not for host or URL lists. If those cannot be told apart without changing `gate_id` itself,
keep a separate digest in `backend.py`, computed from what the scanner already exposes. Say what you chose.
A verdict cache that relies on `gate_id` must keep working as it does.

**3. The events table is never trimmed.** Add a method to `db.py` that keeps the newest events up to a
bound, about 20,000, and call it from `_maintain` next to `prune_cache`. Quarantine records and anything
that action recovery reads are separate tables and must stay untouched; check that `events` is only a log
and that `after` paging by id still works when old rows have gone.
