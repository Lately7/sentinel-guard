# Codex fix round FIX18: findings of RED11

Worktree: the RED11 worktree, synced with `main`. The round's tests are
`tests/codex/test_red11_lifecycle.py`, its report
`docs/research/RED11-lifecycle.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_pipe_setup_failure_stops_started_backend`: **hardening**, low.
* `test_slow_start_advances_pending_checkpoint`: **product_bug**, low.
* `test_pipe_listener_death_fails_service`: **hardening**, low.
* `test_observer_stop_failure_still_revokes_barrier`: **hardening**, low.
* `test_failure_actions_keep_restarting_after_third_crash`: **by_design**, low.
* `test_restart_settles_recent_crashed_quarantine`: **hardening**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
