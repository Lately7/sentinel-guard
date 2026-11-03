# Codex fix round FIX6: findings of RED4

Worktree: the RED4 worktree, synced with `main`. The round's tests are
`tests/codex/test_red4_nativehost.py`, its report
`docs/research/RED4-nativehost.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_offline_service_does_not_grant_local_host_trust`: **hardening**, low.
* `test_changed_download_is_not_reported_clean_from_stale_service_verdict`: **test_bug**, none.
* `test_completed_blocked_url_download_keeps_source_warning`: **product_bug**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
