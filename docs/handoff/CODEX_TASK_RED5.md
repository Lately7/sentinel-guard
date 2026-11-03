# Codex red team round RED5: Feeds, indicators and rule publishing

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red5_feeds.py` and `docs/research/RED5-feeds.md`. Everything else is read-only.

## Scope

`agent/sentinel/feeds.py`, `indicators.py`, `yarafeed.py`, `db.py` publish paths, and anything they call that matters to the attack.

## Probe at least

Hostile or broken feed content: huge lines, NUL bytes, invalid UTF-8, Unicode look-alike hosts, duplicate and conflicting entries, a feed that allow-lists by accident, a rule set that compiles but matches everything or nothing, a publish interrupted half way (power loss), two publishes racing, a snapshot file swapped by the user, rollback to an older generation, and whether any of these silently empties protection.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
