# Codex fix round FIX7: findings of RED5

Worktree: the RED5 worktree, synced with `main`. The round's tests are
`tests/codex/test_red5_feeds.py`, its report
`docs/research/RED5-feeds.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_red5_truncated_nonempty_feed_keeps_previous_indicators`: **hardening**, medium.
* `test_red5_duplicate_url_sources_survive_one_feed_failure`: **product_bug**, low.
* `test_red5_missing_published_snapshot_is_unhealthy`: **product_bug**, low.
* `test_red5_stale_publish_cleanup_keeps_newest_snapshot`: **hardening**, low.
* `test_red5_repeated_tranco_rows_cannot_allow_blocked_host`: **hardening**, low.
* `test_red5_yara_trial_rejects_match_on_empty_input`: **hardening**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
