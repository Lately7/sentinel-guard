# Codex task — Gate v2 milestone 4, round 2: review fixes

Same rules as `CODEX_TASK_GATE_V2_M4.md`. Worktree `..\sentinel-guard-gate-v2`,
branch `codex/gate-v2-m4`; HEAD must be **648e85f** (your round-1 files,
committed by Claude), else stop and report. Allowed paths:
`agent/sentinel/gate_v2/`, `tests/gate_v2/`. Do not commit.

Claude ran `tests/gate_v2` outside the sandbox: **1 failed, 202 passed**, and
read every line. The strict reply parser, the readiness fields, the reload
target and the TCP-owner lookup (`winnet.py`) are good. Fix these; each needs
a test that fails on 648e85f and passes after.

## Must fix

**J1 — every real scan longer than 0.25 s times out.** `_reply()` sets a
0.25 s socket timeout and raises `TIMEOUT` on the first `socket.timeout`;
`_connect()` and the per-chunk `sendall` use the same 0.25 s. clamd answers
`INSTREAM` only after scanning, which takes seconds for large files, so a
real daemon would make almost every non-trivial scan `TIMEOUT` (the fake
server answers instantly, so the tests did not notice). Required: wait until
the request deadline (also cap one INSTREAM at a configurable maximum, e.g.
150 s as in `engine/clamav.py`), polling in short slices only to notice
cancellation; the same for `sendall` (send in slices or with the remaining
time) and for connect (a few seconds at most, within the deadline). Tests: a
fake clamd that waits ~1 s before `stream: OK` → `COMPLETED`; one that never
answers → `TIMEOUT` at the deadline, not after 0.25 s; cancel during the wait
→ `CANCELLED` within a fraction of a second.

**J2 — `test_timeout_and_refusal` fails on Windows.** Connecting to a closed
local port is refused only after Windows' SYN retries (~1–2 s), so the 0.25 s
connect timeout reports `TIMEOUT` instead of `UNAVAILABLE`. With J1's connect
budget, a refused connection must come out `UNAVAILABLE`; keep the test
deterministic (a port you just bound and closed).

**J3 — readiness on every file.** Each `scan_bound` runs PING and VERSION on
two new connections plus a full TCP-table walk before the INSTREAM. Cache the
readiness result for a short TTL (e.g. 5 s, injected clock), invalidate it on
`request_reload`, on any transport/protocol error and when the scan
connection's owner check fails; the INSTREAM connection's owner is still
verified on every scan. Test: three scans within the TTL send PING/VERSION
once; an error forces a fresh readiness check.

**J4 — a failed reload freezes ClamAV as unverified.** If `RELOAD` is not
answered `RELOADING` (or the connection fails), `_reload_target` stays set and
readiness reports `RELOAD_PENDING` forever, although RT-030 says a failed
reload keeps the **old** engine active. Required: a refused/failed RELOAD
clears the target and records a typed `RELOAD_FAILED` readiness note; an
acknowledged reload whose new daily version does not appear within a bounded
window (injected clock) also ends as `RELOAD_FAILED`, after which the old,
still-reported generation is treated as active again (trusted if everything
else is verified), and its `generation_digest` stays the old one. Tests for
both paths.

## Running the tests

`..\sentinel-guard\.venv\Scripts\python -m pytest -q tests/gate_v2 -p no:cacheprovider`
If the sandbox refuses temp folders or sockets, report it and stop; create no
folders. Claude runs everything outside the sandbox.

## Your answer

English, concise: per finding, change (file:line) and test name; the exact
command and real output; disagreements.
