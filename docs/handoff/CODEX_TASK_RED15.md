# Codex red team round RED15: Concurrency across clients

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red15_concurrency.py` and `docs/research/RED15-concurrency.md`. Everything else is read-only.

## Scope

`agent/sentinel/service/core.py`, `backend.py` lanes, `workerclient.py`, `db.py`, and anything they call that matters to the attack.

## Probe at least

Several clients on the pipe at once (tray, native host, CLI, a hostile medium process), the same file scanned by two lanes, a quarantine racing a scan of the same path, rate limits that a hostile client can use to starve the tray, lock ordering between the backend, the database and the worker, and stop during each of these.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
