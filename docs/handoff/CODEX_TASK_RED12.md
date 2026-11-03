# Codex red team round RED12: The browser extension itself

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red12_extension.py` and `docs/research/RED12-extension.md`. Everything else is read-only.

## Scope

`extension/src/` (background, content scripts, manifest), and what it sends to the native host, and anything they call that matters to the attack.

## Probe at least

Content-script isolation, messages from pages that the background trusts, `externally_connectable` and message origin checks, CSP, storage that a page can influence, how download events map to files on disk (a page renaming or racing a download), notification spoofing, and anything in the manifest that grants more than needed.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
