# Codex red team round RED27: The browser extension, second pass

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red27_extension2.py` and `docs/research/RED27-extension2.md`. Everything else is read-only.

## Scope

`extension/src/`, `extension/manifest.json`, `agent/sentinel/nativehost.py`; `docs/research/RED4-nativehost.md` and `RED12-extension.md` list what earlier rounds found, and anything they call that matters to the attack.

## Probe at least

Only findings those reports do not list. Message flows from pages and content scripts to the background and the native host, download handling across renames and resumes, the allow-host approval UX, and storage.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
