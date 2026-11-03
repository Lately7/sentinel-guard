# Codex red team round RED11: Service lifecycle, crash and recovery

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red11_lifecycle.py` and `docs/research/RED11-lifecycle.md`. Everything else is read-only.

## Scope

`agent/sentinel/service/host.py`, `entry.py`, `backend.py` start and stop, failure actions in `installer.py`, and anything they call that matters to the attack.

## Probe at least

A crash or kill at every step of start and stop, a stop arriving during start, the SCM restart after a crash loop, a worker that dies during service stop, leftovers from a previous run (lease files, half-written state, an ETW session from the previous process), two service processes at once, and whether protection reports itself on when part of it is not running.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
