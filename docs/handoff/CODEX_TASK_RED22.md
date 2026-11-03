# Codex red team round RED22: URL, host and domain handling

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red22_urls.py` and `docs/research/RED22-urls.md`. Everything else is read-only.

## Scope

`agent/sentinel/urlintel.py`, host and domain parsing in the native host and extension, the allow and block lists, and anything they call that matters to the attack.

## Probe at least

IDN and punycode look-alikes, trailing dots, ports, userinfo (`user@host`), IPv6 and decimal or octal IPv4 forms, percent-encoding, very long labels, public suffix edge cases, and whether a page can make a blocked host look allowed or an allowed host cover more than the user approved.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
