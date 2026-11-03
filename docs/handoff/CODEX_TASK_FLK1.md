# Codex task FLK1 (read-only): why test_k3_k4 failed once

## Allowed paths

New: `docs/research/FLK1.md`. Everything else is read-only; change no code or test.

## Question

`tests/gate_v2/test_m5_round2.py::test_k3_k4_named_hit_survives_change_and_deadline` failed once in a full run of
about 1,000 tests and has not failed since; nobody has explained it. An earlier flaky concurrency test turned out
to be a real fault (`sqlite3.OperationalError` "database is locked" read as damage, see `REVIEWS.md`), so a flake
here may be a product bug.

Read the test and every code path it exercises. List each dependency on timing, ordering or shared state: wall or
monotonic clock, deadlines, thread scheduling, temporary files and their names, caches, module-level globals, the
database, environment variables, and state other tests in the suite could leave behind. Rank the plausible causes,
each with the exact lines involved. For the top causes, give a deterministic reproduction (for example a
monkeypatch that delays one step) that Claude can run, and the fix: to the test if the test is wrong, to the code
if the code is wrong. Mark every inference as one.
