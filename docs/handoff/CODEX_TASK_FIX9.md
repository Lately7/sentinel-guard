# Codex fix round FIX9: findings of RED7

Worktree: the RED7 worktree, synced with `main`. The round's tests are
`tests/codex/test_red7_consent.py`, its report
`docs/research/RED7-consent.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_long_repair_plan_is_not_silently_cut`: **hardening**, low.
* `test_overview_reports_service_protection_off`: **product_bug**, medium.
* `test_tray_does_not_claim_enabled_after_service_rejects`: **product_bug**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
