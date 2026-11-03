# Codex task SVC9: what the observers cost, and what they can say about gaps

## Allowed paths

Changed: `agent/sentinel/service/observers.py`, `agent/sentinel/service/usn.py`,
`agent/sentinel/service/procwatch.py`. New: `tests/test_svc9.py`. Everything else is read-only.

## Findings

**1. Every record costs an `OpenFileById`, though few files matter.** `usn.py` resolves each changed
record, and the journal tick may now read 16 batches. The record already has the file name, and only
`RISKY_SUFFIXES` are ever scanned. Filter by the record's name before resolving. A rename is a change of
name: a file renamed from `.txt` to `.exe` has the new name in its record, and that must still be resolved.
Keep `records` and `unresolved` honest: say what each counts afterwards, and add `skipped_by_name` to
`report()`. `verify.py` waits for the key `records`, so that key must still appear after the first tick,
even when every record was filtered.

**2. `largest_gap` cannot tell sleep from a stalled observer.** `procwatch.py:140` measures time between
process polls; the machine showed 10,667 s, and nothing says why. Compare wall clock with
`time.monotonic()`, whose behaviour across sleep you must check in the docs for this Python on Windows, or
use `QueryUnbiasedInterruptTime`, which excludes sleep. Report `largest_gap` as time the machine was awake
and add `slept_seconds`. A long awake gap then means a real stall. Keep the existing key meaning what it says
and document the change in a comment.

**3. Journal lag is invisible.** Report per tick how far the cursor is behind the journal's end, as
`journal_lag_bytes`, the latest value, summed over volumes. With the 16-batch limit a lasting lag is how a
coming wrap can be seen before it costs records.
