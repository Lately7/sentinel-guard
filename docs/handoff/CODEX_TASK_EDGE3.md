# Codex task EDGE3: devilish edge cases for the fixed-drive walk, shadow scoring and the journal

## Allowed paths

New: `tests/codex/test_observe_edges.py`. Everything else is read-only; change no product code.

## Goal

The owner asked for "edge case quỷ". Read `agent/sentinel/service/reconcile.py`, `shadow.py`, `usn.py`,
`observers.py` and their tests, then write tests that try to break them, using only `tmp_path` and the temporary
`SENTINEL_HOME` that `tests/conftest.py` sets. Probe, among others:

* The walk: a junction loop (create with `_winapi.CreateJunction`; skip if that fails), a directory replaced by a
  junction between listing and descent, a directory deleted mid-walk, access-denied directories, paths over 260
  characters and `\\?\` forms, names with trailing dots or spaces, a cloud-placeholder attribute set on a file, a
  resume cursor that is corrupted, truncated, huge, from another version, or points at a path that no longer
  exists, a walk restarted after `done`, and a drive that disappears.
* Shadow scoring: a corrupted or truncated state file, timestamps going backwards (sleep or hibernate), 100,000
  distinct pids for capacity eviction, a pid reused by another image, events for a process never seen starting,
  and the report while waiting for a file event source.
* The journal: records whose names hit and miss the name filter at the edges, a lookup failure code for each of
  `GONE`, the quiet window at its exact boundary, the retry list at its bound.

For each test, state in a one-line comment the correct behaviour and why. A test you believe exposes a real bug
stays a plain failing test with `# expected to fail: <why>`; never xfail or skip it. Report those in your final
answer.
