# Codex red team round RED24: Quarantine, a second pass with fresh eyes

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red24_quarantine2.py` and `docs/research/RED24-quarantine2.md`. Everything else is read-only.

## Scope

`agent/sentinel/quarantine.py` and its callers; `docs/research/RED1-quarantine.md` lists what RED1 already found, and anything they call that matters to the attack.

## Probe at least

Only findings RED1 did not report: read its report first and do not repeat it. Look especially at the store's on-disk format, encryption or encoding of held files, metadata integrity, how ids are generated and validated, and the delete path.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
