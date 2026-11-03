# Codex red team round RED10: CLI, configuration and environment

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red10_cli.py` and `docs/research/RED10-cli.md`. Everything else is read-only.

## Scope

`agent/sentinel/__main__.py`, `config.py`, `settings` handling, environment variables, and anything they call that matters to the attack.

## Probe at least

Whether environment variables (`SENTINEL_HOME` and others), settings files or command arguments let an ordinary user redirect what the service or an elevated command reads or writes, disable protection without an approval, or make an elevated command act on attacker-chosen paths.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
