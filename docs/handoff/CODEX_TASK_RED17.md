# Codex red team round RED17: Verdict and evidence integrity end to end

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red17_verdicts.py` and `docs/research/RED17-verdicts.md`. Everything else is read-only.

## Scope

`agent/sentinel/gate_v2/policy.py`, `orchestrator.py`, `engine/`, `actions` and how verdicts reach the UI, and anything they call that matters to the attack.

## Probe at least

Any path where a partial, timed-out, cached or stale result becomes a clean verdict; a cache entry reused for different bytes; engine disagreement resolved toward clean; a verdict shown for one file but recorded for another; and the allow list matching more than the user approved.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
