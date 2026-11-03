# Codex red team round RED13: Repair and persistence handling

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red13_repair.py` and `docs/research/RED13-repair.md`. Everything else is read-only.

## Scope

`agent/sentinel/repair.py` and the paths that call it, and anything they call that matters to the attack.

## Probe at least

Whether undo or repair can be steered to modify registry keys, scheduled tasks, services or files the user did not choose; records that are tampered with between repair and undo; names with special characters; very many persistence entries; and whether repair ever deletes or changes something it did not measure.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
