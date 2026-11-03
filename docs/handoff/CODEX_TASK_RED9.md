# Codex red team round RED9: Process attribution and observation

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red9_process.py` and `docs/research/RED9-process.md`. Everything else is read-only.

## Scope

`agent/sentinel/service/procwatch.py`, `etw.py` (process parts), `observers.py`, `shadow.py`, and anything they call that matters to the attack.

## Probe at least

Ways a process can avoid being offered for scanning or be mis-attributed: pid reuse between event and resolution, image names over 15 characters, a process that exits before resolution, image paths in device or `\\?\` form, a renamed or replaced image after start, very many short-lived processes, and the sampler's and journal's blind spots.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
