# Codex red team round RED6: Content scanning and archives

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red6_gate.py` and `docs/research/RED6-gate.md`. Everything else is read-only.

## Scope

`agent/sentinel/gate_v2/` (content, archive, identity, scope) and `engine/`, and anything they call that matters to the attack.

## Probe at least

Ways a harmless-marker file escapes detection or is reported clean without being read: nesting depth and size limits, zip entries with overlapping data, encrypted or corrupt entries, polyglot files, sparse files, files growing or shrinking during the scan, cloud placeholders, files locked by another process, very many small entries, names that collide after normalization, and every place an incomplete scan could read as clean.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
