# Codex task FLK1B: make test_k3_k4 deterministic

You continue FLK1 in the same worktree; `docs/research/FLK1.md` is your analysis.

## Allowed paths

Changed: `tests/gate_v2/test_m5_round2.py`, only `test_k3_k4_named_hit_survives_change_and_deadline` and any
helper it alone uses. Everything else is read-only; change no product code.

## Build

Apply your cause 1 fix: drive both scans with a fake monotonic clock shared by `scan(clock=...)` and
`DefenderAdapter(clock=...)`, give the first scan an ample deadline, and give the second a deadline just above the
fake clock that the second runner crosses inside `late()` just before it returns its named hit. Assert that each
fake runner was entered, that the first scan's evidence survives as CHANGED and unaccepted, and that the late hit's
evidence survives while the decision is not accepted as malicious. The test must take no real sleeps. Then add,
in the same file, a second test for your cause 1 reproduction (an applicability step slower than the deadline)
that asserts the documented outcome: no runner entered, no evidence, a TIMEOUT-class result.
