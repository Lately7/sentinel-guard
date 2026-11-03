# Codex red team round RED14: Resource exhaustion

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red14_exhaustion.py` and `docs/research/RED14-exhaustion.md`. Everything else is read-only.

## Scope

the service, worker and observers as a whole, and anything they call that matters to the attack.

## Probe at least

Disk full during every write (state, quarantine, logs), memory pressure from very large or very many inputs, handle and thread exhaustion, a directory with a million entries, a path that is a deep chain of junctions, a log that grows without bound, and which of these silently stop protection versus report it.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
