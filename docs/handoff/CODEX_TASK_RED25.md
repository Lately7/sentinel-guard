# Codex red team round RED25: Actions and approved plans end to end

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red25_actions.py` and `docs/research/RED25-actions.md`. Everything else is read-only.

## Scope

`agent/sentinel/service/backend.py` (act_on, execute_plan, describe_plan, lanes), `actions` code, and anything they call that matters to the attack.

## Probe at least

Whether any action (quarantine, restore, delete, trust, exclusion, disable) can run on a target other than the one measured and described: swaps between describe and execute, plans whose parameters resolve differently later, exclusions that cover more than shown, disable that never comes back on, and what a medium-integrity caller can make the service do without an approval.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
