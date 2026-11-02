# Codex design review — round 1 (read-only, session 01a19b4d-b7b0-7240-a851-dbd9aab366ce)

## Question sent by Claude

## Design discussion: Sentinel Guard test and quarantine policy (read-only)

You are reviewing the Sentinel Guard repository in the current directory as an
independent security reviewer and test engineer. This is a design discussion,
not an implementation task: do NOT modify, create or delete any file. Read the
code and give your engineering opinion.

Context: Sentinel Guard is the user's own Windows 11 anti-malware prototype
(Python agent + MV3 browser extension). Read `AGENTS.md` and `README.md` first.
The working tree contains uncommitted work (base commit `01bc342`) that adds a
multi-layer scan gate: `agent/sentinel/engine/scanner.py` (layers: Sentinel core
-> rule packs + YARA-X -> ClamAV via a private clamd, `engine/clamav.py` ->
Microsoft Defender), `Verdict.engines` per-layer status (`engine/verdict.py`),
`scanjob.py`, `gate_ui.py`, `yarafeed.py`, `tests/test_gate.py`. Quarantine is in
`quarantine.py` + `protection.py` (`act_on`), the file watcher in `watcher.py`,
the browser bridge in `nativehost.py`.

Decisions already agreed with the project owner (do not re-argue them):
- Keep the Python core; no Rust rewrite; Loki-RS dropped; capa optional later.
- Order: (1) commit a baseline, (2) Codex writes characterization tests that lock
  current behaviour (known-dangerous behaviour is marked as a known issue rather
  than locked in), (3) Claude introduces "Scanner Contract v1" (per-engine
  result with separate `status` and `verdict`, plus findings, engine_version,
  db_version, coverage, sha256, size, duration_ms, error, contract_version) with
  a backward-compatible layer, (4) Codex regression review, (5) quarantine
  hardening.
- One signature hit from one engine is enough for "malicious"; no voting by
  number of engines.
- Detection policy and auto-quarantine policy become two separate decisions;
  auto-quarantine stays enabled but behind a testable `should_auto_quarantine()`.
- Restore no longer means global trust by hash: restore creates a path+hash
  exception; "Trust" becomes a separate explicit user action.
- The watcher must exclude Sentinel's own data (quarantine, ClamAV database,
  cache, logs) but not all of %LOCALAPPDATA%.

Open questions. For each one give: your recommendation, the reasoning, the
concrete code locations (file:line) involved, and the tests that would prove
it. Point out anything in the agreed decisions that the code contradicts.

Q1. Partial coverage. ClamAV is sent at most the first 400 MB of a file; rule
packs/YARA see the first 64 MB and last 8 MB of oversized files. Proposal: a
partial-coverage scan can never produce a trusted "clean", but a signature hit
inside the scanned portion still allows auto-quarantine (otherwise growing a
file past the size limit would disable auto-quarantine). Agree or not? Edge
cases?

Q2. Which ClamAV detections count as "high confidence" for auto-quarantine?
Today names starting with `Heuristics.` or `PUA.` are MEDIUM (suspicious), all
others CRITICAL. Observed: ClamAV reports `Win.Trojan.Suspect-34` for a ZIP
whose only member is a harmless text file named `docs/invoice.pdf.exe`, i.e. a
container-metadata signature, not a content signature. Options: (a) name-prefix
rules as today, (b) a reviewed allowlist of signature families, (c) treat
container/filename-metadata signatures as suspicious. Which, and how can the
code tell (c) apart reliably from what clamd returns over INSTREAM?

Q3. Scope of Codex round 1 (characterization tests). Candidate groups: native
host message API (7 message types, validation, 1 MB limits), CLI exit codes
0/1/2/3 and `--json`, `Verdict.to_dict()` and `engines`, scan cache,
quarantine/restore sequence, watcher debounce/partial-download/rename/Run-key
handling, and fuzzing malformed ZIP/PE/filenames (with `hypothesis`). What
should be in round 1 versus later, and what are the highest-risk behaviours to
lock first? Which current behaviours do you consider known issues that must be
marked rather than locked?

Q4. Definition of "round passed". Proposal: pytest and node tests green with
known issues marked `xfail(strict=True)`; a scope check script rejecting any
change outside `tests/codex/` and `reports/red-team.md`; every finding in the
report has a status (fixed / rejected with reason / deferred). Note that the
Codex `workspace-write` sandbox may block localhost sockets, which the tests'
fake clamd uses. What would you add or change?

Q5. False-positive / false-negative measurement. A false-positive run over
C:\Windows\System32, C:\Program Files and %LOCALAPPDATA%\Programs was started
but cancelled. False negatives are currently measured only with the EICAR test
string assembled in memory and wrapped in 8 container formats, plus a harmless
marker string matched by a test-only rule. Should measurement happen at the
baseline (before the refactor) or later, and what harmless, synthetic corpus
would make the numbers meaningful? Only harmless synthetic inputs are allowed.

Also list any defect you notice in the uncommitted gate code itself.

Answer in English, structured by Q1..Q5 then "Other defects". Be concrete and
brief; cite file:line. Do not claim to have run anything you did not run.

## Codex answer (verbatim)

## Q1. Partial coverage

**Recommendation: agree.** Coverage and detection confidence must be independent:

- A partial scan with no findings is **incomplete/unknown**, never trusted clean.
- A conclusive signature found in a scanned region is still malicious and may auto-quarantine if `should_auto_quarantine()` considers that signature trustworthy.
- The legacy `label` may temporarily remain `clean` for compatibility, but callers must also inspect aggregate coverage. The UI and API must not present it as fully clean.

Current code does not enforce this distinction. Oversized files can retain a clean label even though Sentinel and YARA are partial ([scanner.py:165](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:165), [scanner.py:181](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:181), [verdict.py:61](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/verdict.py:61)). ClamAV correctly scans the first 400 MB, but a detection loses the fact that coverage was partial because the status becomes simply `detected` ([clamav.py:310](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/clamav.py:310)).

Record exact coverage, for example:

- `full`
- `ranges: [[0, 67108864], [size-8388608, size]]`
- `container_partial` with member/count/expanded-byte limits
- `none`

Important edge cases:

- A full-file hash/blocklist hit is conclusive even when content inspection is partial.
- A hit in the first 400 MB remains actionable; growing the file must not neutralize it.
- Rule conditions spanning the front and tail will not match because the two ranges are scanned separately.
- Archive coverage is different from raw-byte coverage. Clamd has `MaxFiles`, recursion, expanded-size, and scan-time limits ([clamav.py:96](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/clamav.py:96)); with `AlertExceedsMax no`, an `OK` reply may conceal an internal limit.
- File changes between hashing, range scans, ClamAV, and Defender must produce an error/incomplete result, not a mixed verdict.
- A partial metadata-based hit must still pass the Q2 confidence policy.

Tests that prove it:

- Clean files at 64 MB−1, 64 MB+1, 400 MB, and 400 MB+1: only the first is fully covered by all applicable content layers.
- Marker at front, middle blind region, and tail; assert exact reported ranges and expected hit/miss.
- Marker before byte 400 MB in a larger file: malicious and auto-quarantine eligible if the signature is approved.
- Marker after byte 400 MB and outside the YARA tail: incomplete, not clean.
- Full-file bad-hash hit on a >400 MB synthetic file: malicious despite partial content coverage.
- Archive hitting member/count/recursion limits: `container_partial`.
- File mutation during each layer: no trusted clean and no quarantine of mismatched bytes.
- Cached partial results preserve coverage and never become trusted clean.

One specific bug: successful member inspection clears `v.skipped` for an oversized ZIP even though YARA and possibly ClamAV remain partial ([scanner.py:98](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:98)).

## Q2. ClamAV confidence

**Recommendation: option (b) for auto-quarantine—a reviewed, versioned allowlist of high-confidence ClamAV families.** Keep detection and action separate:

- A ClamAV signature hit may still produce the agreed `malicious` detection verdict.
- Only reviewed high-confidence families make `should_auto_quarantine()` true.
- Unknown, generic, `Suspect`, metadata, heuristic, and PUA families should notify but not automatically remove the file.
- `Win.Trojan.Suspect-34` should not auto-quarantine without specific validation.

The current prefix policy is insufficient: every name except `Heuristics.*` and `PUA.*` becomes CRITICAL ([clamav.py:228](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/clamav.py:228)). That directly exposes harmless container metadata signatures to automatic quarantine through [protection.py:23](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/protection.py:23).

Option (c) cannot be implemented reliably from ordinary INSTREAM results. Clamd returns only a signature name; the parser receives no match offset, member, signature type, or indication that the match came from a filename ([clamav.py:217](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/clamav.py:217)). Scanning the archive and extracted members separately can provide a hint, but it is not reliable enough for an automatic destructive decision.

Tests:

- Policy table for `EICAR`, reviewed strong families, `Heuristics.*`, `PUA.*`, `*.Suspect-*`, metadata denylisted families, and unknown names.
- Assert `verdict == malicious` can coexist with `should_auto_quarantine() == False`.
- Harmless ZIP containing `docs/invoice.pdf.exe`: detected but not auto-quarantined.
- Same member containing the harmless test marker under an approved test signature: eligible.
- Several heuristic signals reaching malicious through aggregation: never auto-quarantine without a conclusive finding.
- Real-clamd metadata tests should be observational/version-pinned, not mandatory unit tests, because database updates can change the signature name.

## Q3. Codex characterization scope

### Round 1

Prioritize boundaries most likely to change or cause data loss:

1. **Verdict/Scanner contract surface**
   - Exact `Verdict.to_dict()` shape and finding ordering.
   - All engine statuses: clean, detected, partial, skipped, unavailable, error.
   - Coverage boundaries and legacy compatibility.
   - Cache keys and invalidation after rules, ClamAV database, and configuration changes.
   - Detection versus `should_auto_quarantine()`.

2. **Quarantine safety**
   - Claim → hash verification → encoded copy → DB record → delete.
   - Rollback at every failure point.
   - Concurrent destination creation and changed-file handling.
   - Restore produces a path+hash exception only.
   - Explicit Trust separately creates global trust.

3. **Native-host trust boundary**
   - All seven handlers at [nativehost.py:92](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/nativehost.py:92) through [nativehost.py:168](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/nativehost.py:168).
   - Types, length limits, unknown fields/types, malformed JSON, truncated frames, IDs, and 1 MB input/output behavior.
   - Absolute file-path validation and bounded responses.

4. **CLI compatibility**
   - Exit codes 0/1/2/3, including mixed “malicious plus unreadable” cases.
   - Valid JSON on stdout with diagnostics on stderr.
   - Partial/error results represented in JSON.

5. **Watcher policy as deterministic unit tests**
   - Debounce/resubmit, partial suffixes, rename destination, changed-during-scan.
   - Sentinel data-directory exclusion, including case variants and path-prefix traps.
   - Avoid timing-heavy watchdog integration where possible.

### Later rounds

- Hypothesis fuzzing of ZIP/PE/filenames.
- Long-running debounce/watchdog tests.
- Real registry/Run-key tests.
- Real ClamAV/Defender and performance tests.
- Large corpus and multi-process stress tests.

Deterministic malformed ZIP/PE cases should still be in round 1; broad property fuzzing can wait until the contract is stable.

### Known issues—not behavior to lock

Use strict xfails that assert the desired future behavior:

- Restore currently grants global hash trust ([quarantine.py:110](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/quarantine.py:110)).
- Every malicious score automatically quarantines; no confidence policy exists ([protection.py:23](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/protection.py:23)).
- Partial/error/unreadable scans can still have `label == clean`.
- `Win.Trojan.Suspect-34` is currently CRITICAL.
- Defender failure and timeout are reported by the orchestrator as clean.
- Watcher submissions do not exclude Sentinel’s data directory ([watcher.py:53](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/watcher.py:53)).
- Cache reuse after an incomplete engine run.
- Mixed CLI failure plus detection exit-code precedence, until explicitly defined.

Existing tests already lock two decisions that are now rejected:

- [test_agent.py:31](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/tests/test_agent.py:31) asserts restore adds global trust and suppresses later detection.
- [test_gate.py:109](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/tests/test_gate.py:109) asserts every non-`Heuristics`/`PUA` ClamAV name is conclusive.

Claude should revise those before the characterization scope is frozen.

## Q4. Definition of “round passed”

The proposal is sound with these changes:

- `xfail(strict=True)` tests must assert the **desired** behavior, carry a stable finding ID and reason, and be narrowly scoped. An unexpected pass should fail the round.
- The scope comparison must use the new baseline commit created in step 1, not `01bc342`; otherwise all existing uncommitted gate work appears out of scope.
- Check committed, staged, and unstaged changes, including renames and binary files.
- Record exact commit, Python/Node versions, commands, pass/skip/xfail counts, and whether optional integration suites were run.
- Require every report finding to have a stable ID, severity, evidence, owner, and status: fixed, rejected with reason, or deferred with rationale and target milestone.
- No network, live user database, real quarantine directory, or production settings during mandatory tests.

There is a governance conflict to resolve first: `AGENTS.md` says Codex never edits and Claude owns all tests/reports ([AGENTS.md:9](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/AGENTS.md:9), [AGENTS.md:58](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/AGENTS.md:58)), while the agreed plan says Codex writes tests and `reports/red-team.md`. Update the process document or have Claude apply Codex’s proposed test patch; otherwise the scope policy itself violates repository rules.

For localhost sockets:

- Make most ClamAV tests transport-injected unit tests that do not open a socket.
- Keep one small protocol integration suite using fake clamd on localhost.
- Sandbox inability is a **skip**, not an xfail.
- The round can pass only if that integration suite is subsequently run outside the restricted sandbox and the exact result is recorded. Do not claim it passed based on the skipped run.

Also, if the scope script is itself new, its location must be allowed or it must be supplied before the restricted round; otherwise the allowlist rejects its own creation.

## Q5. FP/FN measurement

**Measure twice:** once immediately after the baseline commit and again after Scanner Contract v1/quarantine hardening, using the identical frozen corpus and manifest. The baseline gives a behavioral comparator; the later run determines whether the refactor regressed it.

Do not restart the System32/Program Files scan under the “synthetic only” restriction. A synthetic corpus cannot estimate real-world antivirus FP/FN rates, so report these as:

- synthetic clean-case alert rate;
- synthetic signal-detection rate;
- coverage-completeness rate;
- error/unavailable rate;
- auto-quarantine eligibility accuracy.

Suggested deterministic harmless corpus:

- Plain UTF-8/UTF-16/text, JSON, HTML, benign JS/PowerShell-looking text.
- Zero-filled, repeated-byte, random, low/high entropy, and compressed blobs.
- Minimal valid PDF, OOXML document/spreadsheet/presentation skeletons, MIME mail.
- ZIP, nested ZIP, tar/gzip/bzip2/xz with benign members.
- Benign executable-looking names, double extensions, Unicode/RTLO names, long names, and reserved-name edge cases.
- Minimal synthetic PE structures: truncated, valid headers, unusual section counts, high-entropy section, overlay/padding.
- Member-count, recursion, compression-ratio, 64 MB, and 400 MB boundaries.
- The harmless `invoice.pdf.exe` ZIP that triggers the observed ClamAV metadata signature.

Synthetic positive coverage:

- EICAR assembled only in memory, as already done at [conftest.py:8](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/tests/conftest.py:8).
- Harmless test marker for disk/watcher/quarantine tests ([conftest.py:12](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/tests/conftest.py:12)).
- Test-only bad hashes and blocklisted origins.
- Markers at the front, just beyond 64 MB, middle blind region, tail, just below/above 400 MB.
- The eight existing in-memory container forms at [test_gate.py:353](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/tests/test_gate.py:353).

Every corpus entry should have a manifest describing expected detection, coverage, applicable engines, and auto-quarantine eligibility. Record engine/database versions; never reduce the result to a single percentage.

## Other defects

- **Cache identity is weak.** `gate_id()` uses only rule counts and cached ClamAV version ([scanner.py:50](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:50)). Replacing rules while preserving their count reuses stale results. Use content/version digests.
- **Incomplete results are cached.** A clean result with ClamAV/Defender error can later be served after the engine recovers. The 60-second ClamAV version cache also delays invalidation after database reload ([clamav.py:318](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/clamav.py:318)).
- **Defender errors become “clean.”** `defender.scan()` returns the same empty list for clean, timeout, process failure, and malformed output ([defender.py:64](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/defender.py:64)); the scanner maps every empty list to `clean` ([scanner.py:137](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:137)).
- **Cross-layer TOCTOU.** Oversized rule scans and ClamAV reopen the path after hashing; only size/mtime are compared. Same-size replacement with restored timestamps can mix findings from different bytes ([scanner.py:181](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:181), [clamav.py:182](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/clamav.py:182)). Defender always scans the path later.
- **Contradictory engine status.** `pe.inflated` can make the verdict suspicious while Sentinel remains “clean (hash and name only)” and rules/YARA says partial clean ([scanner.py:199](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:199)).
- **Hard-coded coverage text.** The rule coverage string says “first 64 MB” even when the configured limit differs ([scanner.py:208](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:208)).
- **`scan_bytes()` omits Defender status**, so it does not produce the same layer set as `scan_file()` ([scanner.py:147](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:147)).
- **Native framing assumes one read returns the complete body.** A short read becomes bad JSON rather than a truncated-message error or exact-read loop ([nativehost.py:179](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/nativehost.py:179)).
- **CLI walking does not exclude Sentinel data at all** ([__main__.py:14](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/__main__.py:14)); on-demand `ScanJob` does, but its comparison is not canonicalized with `realpath` ([scanjob.py:42](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/scanjob.py:42)).
- **Signature-hit semantics remain ambiguous.** A single YARA Forge HIGH match scores 45 and is only suspicious, not malicious ([signatures.py:97](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/signatures.py:97), [verdict.py:61](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/verdict.py:61)). If “one signature hit” includes reviewed YARA/rule-pack hits, current code contradicts the agreed decision; the contract needs an explicit engine verdict/confidence rather than inferring it from severity.

I performed a read-only code review only. I did not run pytest, Node tests, ClamAV, Defender, or any benchmarks.