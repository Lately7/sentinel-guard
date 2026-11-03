# Codex red team round RED1: Quarantine, restore and delete

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red1_quarantine.py` and `docs/research/RED1-quarantine.md`. Everything else is read-only.

## Scope

`agent/sentinel/quarantine.py`, the quarantine branches of `service/backend.py`, `actions` code they call, and anything they call that matters to the attack.

## Probe at least

Path tricks on the original and restore paths: junctions and symlinks swapped in between measure and move, hard links to a protected file, alternate data streams, 8.3 names, trailing dots and spaces, `\\?\` and UNC forms, a file replaced after it was hashed (does quarantine ever act on bytes it did not measure?), a restore target that now exists or is a directory, two restores racing, a quarantine store that is full, corrupted or tampered with by the user, the Zone.Identifier stream.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
