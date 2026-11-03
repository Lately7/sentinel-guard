# Codex red team round RED4: Native host and extension messaging

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red4_nativehost.py` and `docs/research/RED4-nativehost.md`. Everything else is read-only.

## Scope

`agent/sentinel/nativehost.py`, `extension/src/*.js`, `agent/sentinel/bridge.py`, and anything they call that matters to the attack.

## Probe at least

What a malicious page can make the extension and native host do: forge scan or allow-host requests, abuse approval prompts (fatigue, spoofed hosts, IDN and punycode look-alikes, very long hosts), message sizes at and over the native messaging limits, paths in messages that point at files the page should not reach, races between a download finishing and its scan, a page that keeps the native host busy.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
