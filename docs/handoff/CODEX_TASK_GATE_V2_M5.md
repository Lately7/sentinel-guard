# Codex task — Gate v2 milestone 5: Defender adapter and structural context

You are the implementer of Gate v2. Claude reviews every line, runs the tests
and merges. Read the review records of milestones 1–4 in `REVIEWS.md` (F, G,
H, J findings) first and do not repeat them — in particular: a dropped or
unaccepted detection must never become clean (F1), a returned result must not
be thrown away (G2), "inspected" must mean checked (H1), caps must not drop a
conclusive hit (H7), and every wait must be bounded by the request deadline,
not by a short fixed timeout (J1).

## Pinned start

Worktree `..\sentinel-guard-gate-v2`, branch `codex/gate-v2-m5`, start
commit **8aefd3d**; otherwise stop and report.

## Allowed paths

`agent/sentinel/gate_v2/` and `tests/gate_v2/` only: new `defender.py` and a
new package `gate_v2/analyzers/` (`lnk.py`, `signer.py`, `motw.py`, and
`__init__.py`). M1–M4 modules change only where M5 needs it; list each
change. `agent/sentinel/engine/defender.py`, `engine/motw.py` and all other
code outside `gate_v2/` are **read-only** (integration is milestone 6). Do
not commit.

**Sandbox note:** you cannot run pytest in this sandbox (temp folder denied).
That is *not* a reason to stop: implement everything, re-read your code
against each test, and say which test covers what. Claude runs the suites.
Never create temp or probe folders.

## Read first

R11 §1 (Defender row), §2, §5 rows Defender and Structural analyzers, §6,
§7 row Defender; `docs/research/R13b-design-discussion.md` P4 (Defender is
invoked by the service with argv and `shell=False`; a path result is bound
to the measured generation by before/after identity checks — Claude's
reservation: **no on-disk snapshot copy**, because Defender or Malwarebytes
may quarantine the copy itself); `REVIEWS.md` round-1 note "Defender false
positives" (Defender passive under Malwarebytes, exit 2 without a named
threat is not a detection) and RT-008; current `engine/defender.py:25-133`,
`engine/motw.py`, `engine/scanner.py:340-379` (certificate presence).

## What to build

1. **`defender.py` — `DefenderAdapter` (`engine_id="defender"`,
   `reopens_path=True`).**
   * Applicability first, as an injected callable (current code asks
     Security Center): not installed / not active (passive) → typed
     `UNAVAILABLE` with a readiness code, never clean; cached with a TTL
     (current code: 600 s).
   * Scan through an **injected runner** (argv list, `shell=False`, never a
     command string): `MpCmdRun.exe -Scan -ScanType 3 -File <path>
     -DisableRemediation`, bounded by the request deadline (current 90 s
     cap). The real runner starts the child in a **Job Object** with
     kill-on-close so cancellation/timeout terminates it (you may reuse the
     pattern of `agent/sentinel/service/worker.py` by reading it; do not
     import from `sentinel.service`).
   * Parse conservatively (R11 §6): exit `0` → completed negative for the
     outer file; exit `2` **with** a parsed, bounded `Threat :` name →
     conclusive; exit `2` without a name, any other exit code, unparsable or
     over-long output → `ERROR`; timeout → `TIMEOUT`; `OSError` →
     `UNAVAILABLE`. Raw output never leaves the adapter except a bounded,
     sanitised threat name.
   * Binding: the orchestrator's `reopens_path` revalidation (M2) already
     rechecks identity before and after; additionally refuse to report a
     negative when the file vanished or changed (`CHANGED`). Coverage is
     `declared` outer bytes (Defender gives no coverage detail).
2. **`analyzers/` — context only (never `MALWARE` + `CONCLUSIVE`, never
   enough for `malicious`, invariant 6).** Each is a bound adapter
   (`scan_bound`) working from the M3 `BoundReader`, bounded and total
   (hostile input never raises):
   * `lnk.py`: parse the Shell Link header and the target/arguments strings
     (MS-SHLLINK) within limits; evidence such as `LNK_TARGETS_SCRIPT_HOST`
     (powershell/cmd/mshta/wscript/rundll32 with arguments) → `SUPPORTING`;
     malformed → coverage reason, not clean-by-default.
   * `signer.py`: distinguish **certificate present** (from the PE security
     directory) from **Windows trust verified**. The trust check is an
     injected callable (the real one: `WinVerifyTrust` via `ctypes`, with
     no revocation network fetch by default, returning valid / unsigned /
     invalid / revoked / unavailable — R11 §5). Result is `CONTEXT` evidence
     only; "valid signature" can never lower another engine's detection.
   * `motw.py`: Zone.Identifier context (`ZoneId`, `HostUrl`,
     `ReferrerUrl`, bounded) passed in as already-read text by the caller
     (an injected reader), never trusted as authority: `ORIGIN`/`CONTEXT`.
3. Policy: if M1 `policy.py` needs a tweak so that context-category
   evidence stays context, change it with a test.

## Required tests (`tests/gate_v2/`)

Injected runner for Defender: exit 0; exit 2 with `Threat : Virus:DOS/EICAR_Test_File`
(text only, no file content); exit 2 without a name; exit 1/other; garbled and
over-long output; timeout (runner sleeps past the deadline → `TIMEOUT`, and
the runner was told to kill); `OSError`; not active (passive) → `UNAVAILABLE`;
file swapped between measure and the Defender stage → `CHANGED` through the
orchestrator; a conclusive Defender hit with every other stage clean →
`malicious`. No real `MpCmdRun` is run in tests; one optional Windows test
may check that the real runner's argv is built without a shell (inspect, do
not execute).

Analyzers: synthetic LNK bytes (valid, script-host target, truncated,
hostile lengths); synthetic PE with and without a security-directory entry
(presence ≠ trust); fake trust results for each state; MotW text with each
zone and malformed lines. Each verdict ≤ suspicious when alone.

## Constraints

Python 3.12+, typed, stdlib only, small modules, comments explain why, LF.
Harmless synthetic inputs only; no EICAR on disk; no network. Stricter
reading when R11 is ambiguous; list ambiguities.

## Your answer

English, concise: files and line counts, API, invariant/RT → test mapping,
changes to M1–M4 files and why, open points for milestone 6.
