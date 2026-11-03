# Codex red team round RED3: Worker isolation and the worker protocol

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red3_worker.py` and `docs/research/RED3-worker.md`. Everything else is read-only.

## Scope

`agent/sentinel/service/worker.py`, `service/workerclient.py`, `service/protocol.py`, the worker entry point, and anything they call that matters to the attack.

## Probe at least

What a scanned file can do to the worker and through it to the service: frames from the worker that are huge, slow, malformed or out of order, a worker that answers clean for a file it never read, a hang at each step, stderr flooding, a worker that exits mid-frame, the job and token limits, the window station and desktop, handle inheritance, the scratch directory, and whether the service ever trusts a worker verdict it should not.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
