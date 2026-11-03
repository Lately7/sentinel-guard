# Codex task VER2: verify proves an ordinary token cannot approve

## Allowed paths

Changed: `agent/sentinel/service/verify.py`. New: `agent/sentinel/service/lowclient.py` if a separate module is
cleaner, and `tests/test_ver2.py`. Everything else is read-only.

## Why

`sentinel service verify` runs elevated from `tools/install_service.cmd`. Its `medium_token_cannot_approve` line is
always SKIP ("needs an unelevated client: the tray's Khôi phục shows it"), so the one property that matters most
for approvals, that an ordinary (medium-integrity, unelevated) process cannot approve a privileged plan, is never
checked on the real install. Read `agent/sentinel/service/core.py`, `protocol.py`, `consent.py` and `bridge.py` to
see exactly what an approval needs and which refusal an ordinary client gets.

## Build

1. From the elevated verify, obtain the unelevated token of the same logon without any prompt and without changing
   any setting: with a split-token administrator, `GetTokenInformation(TokenLinkedToken)` on the process token
   returns it. If the token is not split (UAC off, or the built-in Administrator), SKIP with that reason.
2. Start a short client under that token (`CreateProcessWithTokenW` or `CreateProcessAsUserW`, argv array, no
   shell, no window), running the installed runtime's Python the way the service's own clients run, that asks the
   service for an approval-gated action it must refuse, and reports the refusal code on stdout as JSON.
3. PASS only if the service refused for the reason an unelevated caller gets; FAIL only if the unelevated client
   got an approval; every other outcome (cannot get the token, cannot start the client, timeout of 15 s, pipe
   unavailable) is SKIP with the reason. Never leave the client running: kill it on timeout.
4. Nothing here may change system or security settings, prompt UAC, or approve anything real. If the request it
   sends could have any effect when wrongly approved, choose another request.

Tests: drive every branch with fakes for the token and process APIs (split token, not split, client refused,
client approved, timeout, start failure). The real path cannot run without elevation; say how Claude can check it
by hand.
