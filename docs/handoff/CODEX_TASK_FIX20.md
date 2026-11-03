# Codex fix round FIX20: findings of RED18

Worktree: the RED18 worktree, synced with `main`. The round's tests are
`tests/codex/test_red18_logs.py`, its report
`docs/research/RED18-logs.md`.

`TRIAGE.json` in the worktree root holds Claude's triage of each failing test: the verdict after a skeptic tried
to refute it, the lines involved, the reasoning, and a proposed fix. Read it first; do not commit it or edit it.

## Allowed paths

The product files that `TRIAGE.json` names for the findings you fix, the round's test file and its report. Touch
nothing else; if a fix needs another file, stop and say which and why.

## Findings

* `test_system_owned_event_is_not_disclosed_to_medium_caller`: **by_design**, low.
* `test_failed_restore_escapes_run_value_before_logging`: **product_bug**, low.
* `test_bidi_filename_is_escaped_in_threat_event`: **hardening**, low.
* `test_overview_respects_service_realtime_off`: **product_bug**, medium.

Act on each verdict as `CODEX_FIX_COMMON.md` (prepended) says. A finding already fixed on `main` (its test now
passes after the sync) needs nothing beyond saying so.
