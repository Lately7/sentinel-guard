# Codex fix round FIX11: findings of RED9

Worktree: the RED9 worktree, synced with `main`. The round's tests are
`tests/codex/test_red9_process.py`, its report
`docs/research/RED9-process.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_transient_process_image_failure_is_retried`: **hardening**, low.
* `test_etw_start_rejects_reused_pid_even_with_matching_short_name`: **test_bug**, none.
* `test_etw_accepts_extended_drive_image_path`: **test_bug**, none.
* `test_replaced_image_at_recent_path_gets_new_process_offer`: **product_bug**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
