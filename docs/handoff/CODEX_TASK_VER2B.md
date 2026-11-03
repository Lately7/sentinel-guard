# Codex task VER2B: a token that can start the ordinary client

You continue VER2 in the same worktree; its uncommitted changes (`verify.py`, `lowclient.py`, `tests/test_ver2.py`)
are yours to keep and change.

## Allowed paths

Changed: `agent/sentinel/service/verify.py`, `agent/sentinel/service/lowclient.py`, `tests/test_ver2.py`.
Everything else is read-only.

## The problem Claude found in review

`TokenLinkedToken` returns a primary token only to a caller holding SeTcbPrivilege. An elevated administrator
without it gets an impersonation token at SecurityIdentification level (see the TOKEN_LINKED_TOKEN remarks in
Microsoft's documentation; confirm this), which `CreateProcessWithTokenW` cannot use to start a process. On the
owner's install the check would then always be SKIP.

## Build

1. Keep `TokenElevationType` to decide whether the session has a split token (not split: SKIP as today).
2. Start the client with the token of the interactive shell instead, the method Microsoft documents for starting an
   unelevated process from an elevated one: `GetShellWindow`, `GetWindowThreadProcessId`, `OpenProcess` with
   `PROCESS_QUERY_LIMITED_INFORMATION`, `OpenProcessToken` with `TOKEN_DUPLICATE`, then `DuplicateTokenEx` to a
   primary token with `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT |
   TOKEN_ADJUST_SESSIONID`, then `CreateProcessWithTokenW`. No shell window (no interactive shell, another session):
   SKIP with that reason. Verify the shell's process belongs to the same session as the verify process; otherwise
   SKIP. Close every handle on every path.
3. The client keeps confirming for itself that it runs at medium integrity and not as an administrator; anything
   else stays SKIP. PASS and FAIL keep their meaning.

Tests: drive each new branch with fakes (no shell window, other session, OpenProcess or DuplicateTokenEx failure,
success). Say which API facts you confirmed in Microsoft's documentation, with links.
