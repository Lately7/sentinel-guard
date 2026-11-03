# Codex fix round FIX5: findings of RED3

Worktree: the RED3 worktree, synced with `main`. The round's tests are
`tests/codex/test_red3_worker.py`, its report
`docs/research/RED3-worker.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_unsolicited_worker_frames_have_bounded_parent_buffer`: **product_bug**, medium.
* `test_worker_pipe_write_obeys_scan_deadline`: **product_bug**, medium.
* `test_worker_clean_claim_requires_proof_of_stage_read`: **by_design**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
