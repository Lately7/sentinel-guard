# Codex task SVC18B: review fixes for the phased ETW check

## Allowed paths

Changed: `agent/sentinel/service/etw.py`. New: `tests/test_svc18b.py`. `tests/test_svc18.py` only where it pins
behaviour this round changes. Everything else is read-only.

## Context

SVC18 (merged on `main`) added the phased start check in `etw.py`: connect wait, enable, a fixed 7 s schedule
(child A, child B at 3 s, FLUSH at 5 and 6 s), per-phase tallies taken in `Collector.callback`, and `etw check:`
log lines. An adversarial review confirmed the nine defects below; each had a second agent try to refute it and
fail. Threads: the consumer thread (ProcessTrace -> `Collector.callback`), the aggregator (`Collector._aggregate`,
which parses and calls `_check_raw_event` then `_parsed`), the observe-etw thread (`EtwObserver._start`,
`_check_schema`), and the service-stop path (`EtwObserver.stop`, then `MachineObservers.stop` joins observe-etw
for only 0.2 s and the process may exit; every service thread is a daemon).

## Fix

1. **A losing stopper returns before the stop is done (C1, C5).** `Collector.stop` returns at once for a second
   caller while the first is still inside `backend.stop()` (STOP, a wait of up to 3 s for ProcessTrace, joins). A
   service stop then finishes and the process can exit before the failed check's `etw check: stop` line is
   written; separately, `EtwObserver.stop` decides whether to log from `state == "checking"`, which is already
   the failure reason between the state write and `_stop_check`, so nobody logs. Fix: the first caller records a
   deadline (6 s) under `_stop_lock` and sets a `_stop_done` Event in a `finally`; a later caller waits on it for
   what is left of that deadline and returns False. In `EtwObserver`, write the stop line from one helper, once,
   by whichever call actually stopped; decide "the check did not pass" from `collector.phase is not None` read
   under `_lifecycle` (phase becomes None only on the pass path, under `_lifecycle`), not from `state`; and make
   `EtwObserver.stop` wait (bounded, about 6.5 s, under the 10 s service stop hint) for that line when its own
   `collector.stop()` returned False and the check did not pass. A pass keeps today's path with no wait.
2. **The phase is stamped after the queue, not at the callback (C2, C7).** `_parsed` stamps
   `_check_event_phases` with `collector.phase` when the aggregator parses the event, up to 200 ms after the
   callback (the aggregator can sit in `queue.get(timeout=0.2)` on the normal lane), so boundary events get the
   next phase: a false F pass that turns on `flush_assist`, or a false B. Fix: add a trailing
   `phase: str | None = None` to `RawEvent`; `Collector.callback` reads `self.phase` once and passes it to
   `_measure` and to the queued `RawEvent`; `_check_raw_event` stamps `_check_event_phases` for Process Starts
   from `raw.phase`; `_parsed` no longer stamps. `matched` is the earliest phase in W < B < F across both
   children, not the first one scanned. `_log_result` reports that callback-time phase.
3. **The end of the window (C3, C7).** After the 7 s loop, set the collector phase to `E` (ended), wait up to
   300 ms, interruptible by `_stopping`, for both queues to drain, then rescan once. Starts stamped W, B or F
   count; a Start stamped E is late: the verdict is not a pass, and the result line lists it under `late`.
4. **Mismatch is decided by parsing, not by timing (C3).** A correctly parsed child Start that the aggregator
   handled after the last loop-top scan is classed `schema_process_mismatch` today. Fix: `_check_raw_event`
   already receives `parsed`; record per Start pid whether the parsed event matches (kind process_start, pid,
   parent is the service, image matches). Return `schema_process_mismatch` only when a child pid has a raw Start
   whose parsed form did not match; otherwise `no_start_events`. Keep this in memory only and clear it wherever
   `_raw_start_pids` is cleared.
5. **"S" can be overwritten, and B spawned after the stop began (C4).** Add `Collector.set_phase(phase) -> bool`
   that, under `_measure_lock`, refuses to leave "S"; use it for every phase change outside the two stop paths,
   which set "S" under the same lock. In `_check_schema`, stop after a `_phase_end` if `_stopping` is set, and
   do not spawn B when `set_phase` returned False or `_stopping` is set.
6. **The pass path can set "on" after a stop (C6).** Re-check `_stopping` under `_lock` immediately before
   setting `state = "on"`; return if set (stop() is waiting on `_lifecycle` and stops the collector). Do not hold
   `_lock` across `collector.stop()`: the aggregator takes `_lock` while it is being joined.
7. **The sleep gauge counts the check's own work (C8).** Measure only `time.sleep` itself with `perf_counter`;
   when the slot is already past, record the overrun separately (`overrun_ms`). Log both in each phase line and
   reset the worst values after each phase line, so each line carries its own.
8. **A failed spawn of B fails the whole check (C9).** Spawn B at most once; on `OSError`,
   `SubprocessError` or `ValueError` record the error code under `spawn_errors["B"]` and keep the schedule. A's
   failure still propagates as `schema_check_failed`. The result line includes `spawn_errors` (labels and codes
   only).

Refuted, do not change: reading ProcessorIndex from `BufferContext` without checking the processor-index flag.

Every fix needs a test that fails before it, in `tests/test_svc18b.py`; threads in tests must finish within a
second or two (use Events, not sleeps). Keep the privacy rule: nothing about processes other than the service
and its two children reaches the log beyond counts.
