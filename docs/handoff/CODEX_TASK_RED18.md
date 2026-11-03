# Codex red team round RED18: Logs, events and privacy

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red18_logs.py` and `docs/research/RED18-logs.md`. Everything else is read-only.

## Scope

`agent/sentinel/service/` logging, `db.py` events, the `etw check:` lines, `overview_ui.py`, and anything they call that matters to the attack.

## Probe at least

Log injection through file names, command lines or URLs (newlines, control and bidi characters), private data of other users or other processes reaching a log or an event a medium process can read, log files a medium process can write or replace, and unbounded log growth.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
