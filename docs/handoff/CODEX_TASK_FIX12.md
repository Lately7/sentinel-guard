# Codex fix round FIX12: findings of RED10

Worktree: the RED10 worktree, synced with `main`. The round's tests are
`tests/codex/test_red10_cli.py`, its report
`docs/research/RED10-cli.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_defender_path_ignores_user_programdata`: **hardening**, low.
* `test_clamav_update_ignores_user_binary_override`: **by_design**, none.
* `test_service_verify_ignores_user_systemroot`: **hardening**, low.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
