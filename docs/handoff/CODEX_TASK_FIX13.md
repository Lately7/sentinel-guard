# Codex fix round FIX13: findings of RED12

Worktree: the RED12 worktree, synced with `main`. The round's tests are
`tests/codex/test_red12_extension.py`, its report
`docs/research/RED12-extension.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_download_origin_cannot_quarantine_replacement`: **by_design**, low.
* `test_page_warning_has_browser_owned_surface`: **hardening**, low.
* `test_empty_page_signals_clear_worker_state`: **product_bug**, low.
* `test_blocked_page_requires_verified_context_before_render`: **hardening**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
