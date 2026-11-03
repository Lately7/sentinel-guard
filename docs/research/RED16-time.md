# RED16 — Time and clocks

The tests are in `tests/codex/test_red16_time.py`. They were reviewed against the code but not run, as this round forbids pytest.

## RED16-1 — Wall-clock jump deletes recent download rescan debt — high

- **Attacker model:** crash, sleep, or wall-clock correction at the worst moment; a downloaded file is the target.
- **Steps:** record a newly downloaded file, advance the wall clock by 31 days without 31 days of elapsed time, then publish a new rule generation.
- **Effect:** `expire()` deletes the DB row before `signatures_changed()` queues it. The promised new-rule rescan and fresh first-run scan are lost. The ordinary process scan may still occur, but its `fresh` flag is false.
- **Lines:** `agent/sentinel/service/backend.py:581-584` records `time.time()`; `agent/sentinel/service/rescan.py:92-105` uses wall time for the 30-day TTL; `agent/sentinel/service/rescan.py:135-145` drops the debt before both rescan paths; `agent/sentinel/service/observers.py:307-310` consumes the first-run flag.
- **Fix:** preserve a monotonic age for records in the current boot and handle a discontinuous wall clock across restarts conservatively. Never delete rescan debt solely because the wall clock jumped forward; retain it until genuinely aged out or successfully rescanned.
- **Proof:** `test_forward_clock_jump_keeps_recent_download_rescan_debt` proves deletion and lost queueing in process.

## RED16-2 — Clock rollback suppresses engine signature updates — high

- **Attacker model:** wall-clock rollback after a successful YARA or ClamAV update.
- **Steps:** save an update at time T, set the clock back, and run the maintenance due check.
- **Effect:** both elapsed-time differences are negative, so updates stay suppressed until wall time passes T plus the period. New signatures are missed for the duration.
- **Lines:** `agent/sentinel/feeds.py:33-45`; YARA call site `agent/sentinel/service/backend.py:263-269`.
- **Fix:** treat stored future update timestamps as clock discontinuities and schedule an update subject to a bounded retry interval, using a monotonic timer within a boot.
- **Proof:** `test_clock_rollback_does_not_suppress_engine_updates` proves the due check returns false after rollback. The length of real-world suppression is inferred.

## RED16-3 — Clock rollback suppresses malicious-host feed updates — high

- **Attacker model:** wall-clock rollback after a feed attempt.
- **Steps:** save a successful feed timestamp and attempt time, roll the clock back, and ask whether a feed refresh is due.
- **Effect:** the early retry guard returns false even when the indicator snapshot is old by elapsed time. Newly malicious hosts and URLs remain absent.
- **Lines:** `agent/sentinel/feeds.py:225-237`; maintenance call site `agent/sentinel/service/backend.py:263-264`.
- **Fix:** recognize future attempt and success timestamps as discontinuities; use monotonic elapsed time within a boot and persist a safe retry policy across restarts.
- **Proof:** `test_clock_rollback_does_not_suppress_indicator_updates` proves the false due result; missed future indicators are inferred.

## RED16-4 — Expired clean cache entry revives after rollback — medium

- **Attacker model:** wall-clock rollback while a previously scanned file remains unchanged.
- **Steps:** store a trusted clean result, observe it expired at the TTL, roll the wall clock back by one second, then look it up again.
- **Effect:** the clean result is returned after it had already expired. The check for `stored_at > now` only covers rollbacks before the initial store, so elapsed trust can exceed the advertised TTL.
- **Lines:** `agent/sentinel/gate_v2/cache.py:96-112` stores wall-time expiry; `agent/sentinel/gate_v2/cache.py:116-150` accepts the revived entry; `agent/sentinel/engine/scanner.py:211-230` serves it instead of rescanning.
- **Fix:** use monotonic age while running, and persist a rollback-resistant expiry state so an already expired row cannot become valid again. Invalidate cached clean rows on a detected rollback.
- **Proof:** `test_expired_clean_cache_does_not_revive_after_clock_rollback` proves revival in process. Exploitation beyond the TTL depends on a clock discontinuity.

## RED16-5 — Pre-1970 mtime prevents file measurement — high

- **Attacker model:** a downloaded file with a crafted modification time, or an ordinary user who sets it.
- **Steps:** write harmless marker bytes and set mtime to one second before the Unix epoch; measure the file.
- **Effect:** the hash is computed, but `FileIdentity` rejects the negative `mtime_ns`, and `measure_stream()` converts the contract error to `UNREADABLE`. The gate returns an unknown result without running the signature analyzers on the marker bytes.
- **Lines:** `agent/sentinel/gate_v2/identity.py:170-180`; `agent/sentinel/gate_v2/contract.py:190-207`; `agent/sentinel/gate_v2/orchestrator.py:153-159`.
- **Fix:** allow signed, bounded mtime values in file identity serialization and cache keys. Treat change time separately; it does not make a negative mtime invalid.
- **Proof:** `test_pre_1970_mtime_does_not_make_file_unreadable` exercises an on-disk timestamp and proves measurement fails today. The gate's unknown result follows from the cited branch.

## Probed without a further finding

Most deadlines and short in-memory TTLs in the service, gate, watcher, Defender and ETW paths use monotonic clocks. File cache keys include a measured SHA-256 and file identity along with mtime, so a crafted future mtime alone does not make different bytes share a cached result. Local timezone and daylight-saving changes do not directly alter the epoch timestamps used by these decisions. Sleep and hibernate may affect how soon periodic maintenance runs, but the code does not prove a separate failure beyond the wall-clock cases above.
