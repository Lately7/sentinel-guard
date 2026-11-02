# Codex task — Gate v2 milestone 2, round 2: review fixes

Same rules as `CODEX_TASK_GATE_V2_M2.md`. Worktree `..\sentinel-guard-gate-v2`,
branch `codex/gate-v2-m2`; HEAD must be **d50a765** (your round-1 files,
committed by Claude for a clean diff), else stop and report. Allowed paths:
`agent/sentinel/gate_v2/`, `tests/gate_v2/`. Do not commit.

Claude ran your tests outside the sandbox: `tests/gate_v2` 145 passed. Claude
read every line. Identity and events are good. Fix these; each needs a test
that fails on d50a765 and passes after your change.

## Must fix

**G1 — wrong import path in `tests/gate_v2/test_m2.py`.** It imports
`agent.sentinel.gate_v2...`; the package is `sentinel` (`pyproject.toml`
puts `agent/` on `sys.path`). The `agent.` spelling only works because the
repository root is also importable, and it loads a **second copy** of every
module, so `isinstance` checks between the two copies can fail. Use
`sentinel.gate_v2` like `test_gate_v2.py`.

**G2 — a returned detection is thrown away on cancel/deadline (invariant 9).**
`orchestrator.scan()` lines 168–174 replace the adapter's returned result with
a synthetic `CANCELLED`/`TIMEOUT` result whenever cancellation or the
deadline is noticed *after* the adapter returned. A conclusive hit found in
that stage is lost, and the file can end `unknown` instead of `malicious`.
Required: a validated result that the adapter returned is kept as it is; only
stages **not yet started** become `CANCELLED`/`TIMEOUT` (an adapter that sees
the token itself returns its own `CANCELLED`/`TIMEOUT`). Update the existing
test (stage two stays `COMPLETED`, three and four `CANCELLED`) and add: stage
two returns a conclusive hit while the token is set → `malicious`, and a
late-but-valid result after the deadline is kept while later stages are
`TIMEOUT`.

**G3 — `scan_many` must pause admission, not fail files.** When the terminal
ledger is full, `scan()` returns `unknown`/`ADMISSION_FULL`, so under a slow
consumer `scan_many` turns real files into unknown results. R11 §3 says
admission **pauses**. Required: `scan_many` (or a helper it uses) waits for
admission — a condition on `EventStream` signalled by `drain_terminal()` and
`release()`, checked with a timeout loop that also honours cancellation
(cancelled while waiting → that file `cancelled`, never clean). Publishers
still never block. A single `scan()` call may keep returning `ADMISSION_FULL`
as a typed result. Test: `terminal_capacity` small, many files, a consumer
thread draining slowly → every file reaches its real verdict; with the
consumer paused and cancel set → waiting files end `cancelled`, the call
returns, nothing hangs (use timeouts in the test).

**G4 — routine stage events fill the terminal ledger.** Every stage end is
published with `terminal=True`. R11 §3: routine progress goes to the
coalescing queue; the never-drop ledger is for detection, error, action and
file-outcome events. Make a stage end terminal only when it has evidence or
its status is error/timeout/changed/cancelled/unverified/unavailable;
`finished` without evidence and `skipped` are progress events. Keep the
admission reservation as an upper bound. Update the event-order test.

**G5 — action inputs are hard-coded.** `scan()` calls `should_auto_quarantine`
with `auto_quarantine=True` and `current_protection_generation=
request.protection_generation`, so the stop barrier (invariant 11) can never
trip and the user setting is ignored. Add explicit keyword parameters to
`scan()`/`scan_many()`: `auto_quarantine: bool` (required, no default) and
`current_protection_generation: Callable[[], int | None]` (default: returns
the request's generation, i.e. on-demand scans), read **after** the stages
finish. Tests: auto-quarantine off → `NOTIFY`/`AUTO_DISABLED`; generation
changes during the scan → `PROTECTION_STOPPED`.

**G6 — re-verify before every proposed quarantine.** Identity is re-checked
only when the verdict is `malicious`; under `legacy-v0` a `suspicious`
decision can still produce `QUARANTINE` (`LEGACY_V0_CLAMAV_NAME`) with
`identity_reverified=True` unchecked. Compute the action first; if it is
`QUARANTINE` and the request has a path, `revalidate(..., rehash=True)` and,
on failure, recompute with `identity_reverified=False`. Test with a legacy-v0
weak ClamAV name and a same-size in-place rewrite before the action.

## Small

* G7: add the identity case the brief asked for and the test lacks: a
  same-size **in-place** rewrite (no rename, so the file ID stays) with the
  mtime restored by `os.utime` → `revalidate(rehash=True)` is `CHANGED`.
* G8: `_change_time` and `_final_path` redefine the ctypes structure and
  argtypes on every call; define them once at module level (Windows only).

## Running the tests

`..\sentinel-guard\.venv\Scripts\python -m pytest -q tests/gate_v2 -p no:cacheprovider`
If the sandbox refuses temp folders, report it and stop there; do **not**
create probe or temp folders in the worktree (Claude had to delete three after
round 1). Claude runs the suite outside the sandbox.

## Your answer

English, concise: per finding, the change (file:line) and the test name; the
exact command and its real output line; anything you disagree with.
