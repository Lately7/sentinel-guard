# Codex fix round FIX14: findings of RED13

Worktree: the RED13 worktree, synced with `main`. The round's tests are
`tests/codex/test_red13_repair.py`, its report
`docs/research/RED13-repair.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_changed_run_type_is_not_removed`: **hardening**, low.
* `test_journal_failure_does_not_lose_run_value`: **product_bug**, low.
* `test_unpaired_surrogate_run_name_retains_undo`: **product_bug**, low.
* `test_undo_preserves_replaced_run_value`: **product_bug**, low.
* `test_failed_undo_keeps_its_journal`: **product_bug**, low.
* `test_renamed_restore_does_not_persist_occupant`: **product_bug**, medium.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
