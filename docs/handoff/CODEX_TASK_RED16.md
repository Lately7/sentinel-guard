# Codex red team round RED16: Time and clocks

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red16_time.py` and `docs/research/RED16-time.md`. Everything else is read-only.

## Scope

every use of `time.time`, `time.monotonic`, file times and deadlines in `agent/sentinel/`, and anything they call that matters to the attack.

## Probe at least

Clock rollback and jumps, sleep and hibernate, daylight saving and time zones, file times in the future or before 1970, deadlines computed from wall time, TTLs that a clock change extends or cuts, and caches keyed on mtime that a crafted file time can poison.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
