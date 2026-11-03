# Codex red team round RED8: Database and state files

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red8_state.py` and `docs/research/RED8-state.md`. Everything else is read-only.

## Scope

`agent/sentinel/db.py`, `config.py`, every JSON or SQLite state file the service and tray keep, and anything they call that matters to the attack.

## Probe at least

Corruption, truncation and tampering of each state file by an ordinary user where it is writable, power loss during writes, two processes opening the same database, a locked database at every call site, disk full, a state directory replaced by a junction, clocks going backwards, and whether any of these turns protection off silently or makes the service crash-loop.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
