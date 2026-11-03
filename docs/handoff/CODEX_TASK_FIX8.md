# Codex fix round FIX8: findings of RED6

Worktree: the RED6 worktree, synced with `main`. The round's tests are
`tests/codex/test_red6_gate.py`, its report
`docs/research/RED6-gate.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_orphan_local_zip_entry_is_not_certified_clean`: **product_bug**, medium.
* `test_same_size_change_during_measurement_is_rejected`: **test_bug**, none.
* `test_fixed_partial_middle_gap_is_not_labeled_clean`: **by_design**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
