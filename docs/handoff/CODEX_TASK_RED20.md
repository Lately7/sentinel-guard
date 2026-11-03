# Codex red team round RED20: The named pipe server and caller identity

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red20_pipe.py` and `docs/research/RED20-pipe.md`. Everything else is read-only.

## Scope

`agent/sentinel/service/winpipe.py`, `server.py` or whatever accepts pipe connections, `core.py` authorize, and anything they call that matters to the attack.

## Probe at least

Pipe ACLs and the integrity label, first-instance squatting before the service creates the pipe, a client that impersonates another session, caller identity derived from impersonation versus process tokens, a client that connects and never sends, many half-open connections, and whether any operation trusts what the client says about itself.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
