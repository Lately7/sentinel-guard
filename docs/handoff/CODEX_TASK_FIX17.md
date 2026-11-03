# Codex fix round FIX17: findings of RED17

Worktree: the RED17 worktree, synced with `main`. The round's tests are
`tests/codex/test_red17_verdicts.py`, its report
`docs/research/RED17-verdicts.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_plan_uses_measured_head_for_defender_applicability`: **product_bug**, low.
* `test_fixed_partial_without_full_negative_cannot_be_clean`: **by_design**, low.
* `test_over_deadline_last_stage_cannot_return_clean`: **by_design**, none.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
