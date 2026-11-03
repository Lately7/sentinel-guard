# Codex fix round FIX10: findings of RED8

Worktree: the RED8 worktree, synced with `main`. The round's tests are
`tests/codex/test_red8_state.py`, its report
`docs/research/RED8-state.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_disk_full_during_open_keeps_original_database`: **product_bug**, medium.
* `test_backward_clock_does_not_defer_updates`: **product_bug**, medium.
* `test_interrupted_settings_save_keeps_previous_settings`: **product_bug**, low.
* `test_missing_published_snapshot_forces_feed_refresh`: **hardening**, low.
* `test_invalid_schema_version_does_not_abort_database_open`: **hardening**, low.
* `test_malformed_feed_timestamp_does_not_stop_scheduler`: **hardening**, low.
* `test_backward_clock_reconciles_future_dated_action`: **hardening**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
