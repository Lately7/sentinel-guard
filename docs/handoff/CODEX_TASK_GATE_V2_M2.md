# Codex task — Gate v2 milestone 2: file identity, orchestrator skeleton, events

You are the implementer of Gate v2 for Sentinel Guard (owner decision
2026-11-02). Claude wrote this task, reviews every line, runs the tests and
decides whether to merge. Milestone 1 (your `contract.py`, `coverage.py`,
`policy.py`) is merged; its review record is in `REVIEWS.md` ("Gate v2
milestone 1") — read it, the same standards apply.

## Pinned start

* Working directory: the git worktree `..\sentinel-guard-gate-v2`, branch
  `codex/gate-v2-m2`.
* Start commit: **8d95a1d** (`git log -1 --format=%h`); if it differs, stop
  and report. This task file is given to you as the prompt.

## Allowed paths

* `agent/sentinel/gate_v2/` and `tests/gate_v2/` only.
* New files: `identity.py`, `orchestrator.py`, `events.py` and their tests.
* M1 files may change only where M2 needs it (for example an additive field);
  list every such change and why in your answer. Do not weaken any M1 test.
* Nothing else changes: not `engine/scanner.py` (the adapter shell waits for
  milestone 6), no other production code, existing tests, docs or config.
  Do not commit. Claude runs
  `tools/check_codex_scope.ps1 -Base 8d95a1d -Allow "agent/sentinel/gate_v2/,tests/gate_v2/"`.

## Read first

R11 (`docs/research/R11-gate-v2-knowledge-pack.md`) §§2, 3 (modules, data
flow, state machine, `ScanEvent` stream), 4, 7 (rows Identity, Concurrency/
cancel, Events) and 8 row 2; `docs/handoff/PROJECT_CONTEXT.md` §§7, 10, 11.

## What to build

1. **`identity.py`** — measure one file generation without trusting the path
   twice. Stdlib only (`os`, `stat`, `hashlib`, `ctypes` for Win32 calls).
   * Open once; take `fstat` before; hash the bytes in bounded chunks from
     the same descriptor; `fstat` after. Any change in size, mtime, ctime or
     file index between the two → a typed "changed" outcome (no exception
     escapes to callers for ordinary I/O failures: return a typed result with
     a stable code such as `UNREADABLE`, `NOT_REGULAR`, `CHANGED`,
     `TOO_LARGE`, `CANCELLED`).
   * `FileIdentity` fields from the handle: `volume_serial` (`st_dev`),
     `file_id_hex` (Python 3.12+ on Windows exposes the 128-bit file ID in
     `st_ino`; format as 32 hex chars), `size`, `sha256`, `mtime_ns`,
     `change_time_ns`, and `canonical_path` from
     `GetFinalPathNameByHandleW` (via `msvcrt.get_osfhandle` + `ctypes`),
     normalised to a plain drive path where Windows returns `\\?\`. On a
     non-Windows host the canonical path may fall back to `os.path.realpath`
     — document it; tests that need Windows are skipped elsewhere with a
     reason.
   * Bytes input (`ScanRequest.data`) gets an identity with `canonical_path`,
     `volume_serial`, `file_id_hex`, times = `None`.
   * `revalidate(path, expected, *, rehash: bool)` for the moment before an
     action or after a path-based engine: reopen, compare volume/file ID,
     size and times, and with `rehash=True` also the SHA-256. Metadata
     equality alone is not enough when `rehash=True` (R11 §3: mtime can be
     restored after a same-size swap).
   * Cooperative cancellation between chunks; byte budget (size limit)
     parameter; reading must never load the whole file into memory.
   * No reparse/junction following beyond what `open()` does; record the
     final path from the handle so an alias resolves to one identity.
2. **`events.py`** — the progress channel and terminal ledger of R11 §3
   "ScanEvent stream", in memory (no disk in M2; say what M7 must add for
   durability):
   * Progress events go into a bounded, **non-blocking**, coalescing queue:
     a publisher never waits; when full, events are coalesced (e.g. per
     `(file_id, stage)` keep the latest) and a dropped/coalesced counter is
     kept. Worker-side counters are summed, not queued per event.
   * Terminal events (detection, error, action, file complete/cancelled) go
     into a separate ledger that never drops: it is bounded by **admission
     control** — `admit()` refuses a new file while the ledger's quota is
     full, so workers never block on a paused consumer and terminal events
     are never lost.
   * Monotonic `sequence` per scan; events are `ScanEvent` (no path, hash,
     URL, user name, command line or raw engine output; M1 validation
     already enforces the token format).
   * `snapshot()` for a UI reading at ~10 Hz.
3. **`orchestrator.py`** — `scan(request, *, adapters, stages, cancel,
   gate_generation, emit=None, clock=...) -> FinalDecision` for one file,
   plus `scan_many(...)` with a small worker pool (default 2, maximum 4) for
   several files:
   * Identity first (path or bytes). If identity fails, no engine runs; the
     decision is `unknown` with the identity reason (never clean).
   * Stages of one file run **sequentially** in the given adapter order;
     different files run in parallel. Every enabled adapter yields exactly one
     `EngineResult` (R11 invariant 7): an adapter exception becomes a typed
     `ERROR` result with a bounded, sanitised `ScanError` (never propagates,
     never clean); a result for the wrong `file_id`, wrong identity or wrong
     engine id is replaced by a typed `ERROR`/`CHANGED` result; a deadline
     overrun gives `TIMEOUT` for the current and remaining stages; a
     cancellation gives `CANCELLED` for the stages not yet run (invariant 9).
   * After an **accepted conclusive** hit the remaining stages are `SKIPPED`
     with a reason code (configurable; weak hits never skip later engines —
     RT-035). Already accepted conclusive evidence still reaches a decision
     when the scan is cancelled afterwards.
   * After path-based stages (adapters that declare they reopen the path),
     call `identity.revalidate(..., rehash=True)`; a mismatch makes that
     stage `CHANGED` (invariant 2).
   * Turn `MISSING_IDENTITY` and other `ContractError`s from `decide()` into a
     typed `unknown` decision, not an exception (M1 review note).
   * Emits `started`/`finished`/`skipped`/`error`/`cancelled` events per stage
     through `events.py`; the decision itself comes from M1 `policy.decide()`.
   * The state machine of R11 §3 (queued → opening → hashing → stages →
     deciding → complete/cancelled) is explicit, and illegal transitions raise
     in tests. Actions (`action_pending`/`acting`) stop at the decision in M2:
     `should_auto_quarantine` is called and its `ActionDecision` returned, but
     nothing is moved on disk.

## Required tests (`tests/gate_v2/`)

All file fixtures are harmless synthetic bytes under pytest's `tmp_path`
(the root `tests/conftest.py` sets a temporary `SENTINEL_HOME`; do not
override it). Never write EICAR or any malware to disk; no network.

* Identity: A/B same-size swap with the mtime restored by `os.utime` between
  measure and revalidate → mismatch with `rehash=True`; rename keeps the file
  ID; a hard link resolves to the same file ID; a long (>260 chars) Unicode
  path works (skip with reason if the OS refuses); a file modified during
  hashing (inject a hook between chunks) → `CHANGED`; directory/missing
  file → typed codes; cancellation between chunks → `CANCELLED`.
* Orchestrator with fake adapters: exception → `ERROR` and never clean;
  wrong file_id/identity → rejected; deadline → `TIMEOUT` for the rest;
  cancel during stage 2 of 4 → stages 3–4 `CANCELLED`, decision `unknown`
  (or `malicious` if stage 1 had an accepted conclusive hit); conclusive at
  stage 1 → later stages `SKIPPED`; weak at stage 1 → later stages still run;
  path stage followed by an A/B swap → `CHANGED`; two and four workers over
  many files → no cross-file result mixing, per-file order preserved.
* Events: 500,000 progress events with a paused consumer → bounded resident
  queue length, publisher never blocks (measure with a timeout), coalesced
  count reported; terminal events never dropped and in sequence order;
  admission refused when the ledger quota is full and resumes after the
  consumer drains; privacy (no path/hash in any event).

## Running the tests

`..\sentinel-guard\.venv\Scripts\python -m pytest -q tests/gate_v2 --basetemp .codex-pytest-tmp -p no:cacheprovider`
If the sandbox denies temp folders, say so and do not create probe folders or
work around the root `SENTINEL_HOME` fixture; Claude runs the suite outside
the sandbox. Never report a test as passed unless you saw it pass.

## Constraints

Python 3.12+ (the venv is 3.15), fully type-annotated, stdlib only, small
modules, comments explain why. LF line endings. If R11 is ambiguous, choose
the stricter reading (no false clean, no action) and list it.

## Your answer

English, concise: files and line counts, public API, the R11 invariant →
test mapping, M1 files changed and why, the exact pytest command and its real
output line, and what milestones 6–7 must add (cache, legacy adapter,
durable ledger, actions).
