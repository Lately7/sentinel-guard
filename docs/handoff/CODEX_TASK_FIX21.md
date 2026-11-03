# Codex fix round FIX21: findings of RED19

Worktree: the RED19 worktree, synced with `main`. The round's tests are
`tests/codex/test_red19_etwcheck.py`, its report
`docs/research/RED19-etwcheck.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_reused_child_pid_does_not_log_unrelated_command_line`: **product_bug**, low.
* `test_child_start_does_not_pass_check_after_event_loss`: **by_design**, none.
* `test_dead_consumer_cannot_leave_observer_on`: **hardening**, low.
* `test_service_stop_has_a_real_deadline_when_backend_stalls`: **hardening**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
