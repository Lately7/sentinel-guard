# Codex fix round FIX4: findings of RED1

Worktree: the RED1 worktree, synced with `main`. The round's tests are
`tests/codex/test_red1_quarantine.py`, its report
`docs/research/RED1-quarantine.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_red1_live_quarantine_is_not_reconciled_as_a_crash`: **hardening**, low.
* `test_red1_reconcile_distinguishes_a_same_hash_replacement`: **hardening**, low.
* `test_red1_delete_keeps_blob_if_record_removal_fails`: **hardening**, low.
* `test_red1_zone_mark_added_between_read_and_open_is_preserved`: **hardening**, low.
* `test_red1_service_reports_lost_download_mark`: **product_bug**, none.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
