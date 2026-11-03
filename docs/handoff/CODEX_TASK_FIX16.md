# Codex fix round FIX16: findings of RED15

Worktree: the RED15 worktree, synced with `main`. The round's tests are
`tests/codex/test_red15_concurrency.py`, its report
`docs/research/RED15-concurrency.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_hostile_client_cannot_rate_limit_tray_status`: **by_design**, none.
* `test_hostile_client_cannot_fill_tray_scan_quota`: **by_design**, none.
* `test_disable_timeout_does_not_publish_off_while_action_runs`: **product_bug**, low.
* `test_enable_in_flight_cannot_reopen_barrier_after_stop`: **product_bug**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
