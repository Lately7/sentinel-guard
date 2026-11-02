# Codex task — Gate v2 milestone 4, round 2b: implement J1–J4

Continue `CODEX_TASK_GATE_V2_M4_R2.md` (read it again: findings J1–J4). Same
worktree and branch; HEAD is still **877fd4d** and your uncommitted round-2
test additions in `tests/gate_v2/test_m4_clamd.py` are in place — keep them.

**Correction from Claude.** The previous brief said "if the sandbox refuses
temp folders, report it and stop". That meant *stop trying to run pytest and
do not invent workarounds* — not *stop the task*. You stopped before changing
the adapter, which was my wording's fault. Now:

1. Implement J1–J4 in `agent/sentinel/gate_v2/clamd.py` (and `winnet.py`
   only if needed). Claude already ran your six new tests outside the sandbox
   against 877fd4d: all six fail (`test_delayed_instream_reply_completes`,
   `test_instream_waits_until_deadline`, `test_cancel_during_instream_reply_wait`,
   `test_readiness_cache_reused_and_invalidated_after_error`,
   `test_failed_reload_keeps_old_generation_active`,
   `test_reload_activation_window_expires_to_old_generation`) — some with a
   `TypeError` because the constructor parameters they use do not exist yet.
   Make them pass, and fix J2 (`test_timeout_and_refusal`).
2. You cannot run pytest in this sandbox. Do not try workarounds and do not
   create folders. Re-read your code against each test instead, and say in
   your answer which test covers which change.

Allowed paths: `agent/sentinel/gate_v2/`, `tests/gate_v2/`. Do not commit.

## Your answer

English, concise: per finding J1–J4, the change (file:line) and the test that
covers it; anything you could not finish.
