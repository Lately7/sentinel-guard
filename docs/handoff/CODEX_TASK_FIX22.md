# Codex fix round FIX22: findings of RED20

Worktree: the RED20 worktree, synced with `main`. The round's tests are
`tests/codex/test_red20_pipe.py`, its report
`docs/research/RED20-pipe.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_idle_clients_cannot_exhaust_all_pipe_request_slots`: **product_bug**, medium.
* `test_pipe_name_squatter_cannot_prevent_service_start`: **product_bug**, high.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
