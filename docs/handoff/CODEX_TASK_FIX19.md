# Codex fix round FIX19: findings of RED16

Worktree: the RED16 worktree, synced with `main`. The round's tests are
`tests/codex/test_red16_time.py`, its report
`docs/research/RED16-time.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_pre_1970_mtime_does_not_make_file_unreadable`: **product_bug**, high.
* `test_clock_rollback_does_not_suppress_engine_updates`: **product_bug**, low.
* `test_clock_rollback_does_not_suppress_indicator_updates`: **product_bug**, low.
* `test_forward_clock_jump_keeps_recent_download_rescan_debt`: **hardening**, low.
* `test_expired_clean_cache_does_not_revive_after_clock_rollback`: **hardening**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
