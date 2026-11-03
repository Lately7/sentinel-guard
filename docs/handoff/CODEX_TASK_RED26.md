# Codex red team round RED26: Scan policy and the orchestrator, second pass

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red26_policy.py` and `docs/research/RED26-policy.md`. Everything else is read-only.

## Scope

`agent/sentinel/gate_v2/policy.py`, `orchestrator.py`, `scope.py`, `identity.py`; `docs/research/RED6-gate.md` and `RED17-verdicts.md` list what earlier rounds found, and anything they call that matters to the attack.

## Probe at least

Only findings those reports do not list. Every path from a stage result to a final verdict and to caching: which combination of partial, timeout, unavailable, changed and named results can still end clean or cached; and identity checks that a hard link, a rename or a same-size rewrite can satisfy.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
