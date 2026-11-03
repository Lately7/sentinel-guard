# REVIEWS.md — Codex review log

Codex reviews read-only (`codex exec -s read-only`); Claude checks every
finding against the code, fixes or rejects it, and re-runs the tests.

## Incident before round 1 — database corruption

Two tray instances started together (no single-instance guard) and both ran
a full feed import; the SQLite state DB was left damaged. A second damage
appeared later on the same directory with a single writer; the exact
external cause could not be reproduced (the same code was clean in three
other directories). Fix, independent of the cause:

* Single tray instance (named mutex); a second launch shows the dashboard.
* Feed updates hold a cross-process mutex.
* Feed data moved out of the state DB into immutable snapshot files, built
  fresh on every update and switched to by pointer (`indicators.py`). The
  state DB no longer sees bulk delete/insert churn.
* `check_and_repair()` at start-up: a damaged state DB is moved aside, the
  user's tables (quarantine, allow lists, events, settings) are salvaged.

## Round 1 — 28 findings

| # | Finding | Outcome |
|---|---------|---------|
| 1 | Trusted site used `allowAllRequests`, unblocking malware hosts it embeds | Fixed: scoped `allow` rule |
| 2 | Disabled protection re-enabled itself on sync/restart | Fixed |
| 3 | Large/nested archives silently partially inspected | Partly: >64 MB ZIPs now scanned member-by-member from disk, executables first, limits reported as INFO. Not made "suspicious" — that would flag every large legitimate archive |
| 4 | File swapped between scan and quarantine | Fixed: claim by rename, re-hash, compare |
| 5 | Original deleted before DB record existed | Fixed: record first, compensating rollback |
| 6 | Small download finishes before URL cancel | Fixed: completed-file scan adds the URL verdict |
| 7 | Native messages could exceed 1 MB | Fixed: byte-bounded pages, size guard |
| 8 | Repeated weak findings summed to "malicious" | Fixed: each rule counts once |
| 9 | Growing file read unboundedly | Fixed: read bounded by stat size, re-stat |
| 10 | Quarantine loaded whole file into memory | Fixed: streamed |
| 11 | Page signals active while disabled | Fixed |
| 12 | Stale async verdict applied to newer navigation | Fixed: per-tab navigation sequence |
| 13 | Scans blocked URL lookups in native host | Fixed: scans on worker threads |
| 14 | Warning page context race | Fixed: synchronous record + retry |
| 15 | Dashboard un-trust not synced to extension | Fixed: agent allowlist is authoritative |
| 16 | Some request types not blocked | Fixed: `excludedResourceTypes: [main_frame]` |
| 17 | Malformed settings crashed start-up | Fixed: per-field validation |
| 18 | ASCII `.cmd` launcher broke on non-ASCII paths | Fixed: host is `sentinel.exe` directly |
| 19 | Restore could overwrite an existing file | Fixed: unique name, exclusive create |
| 20 | Temp-suffixed files never scanned | Fixed: scanned after 90 s quiet |
| 21 | Redirected Desktop/Documents not watched | Fixed: `SHGetKnownFolderPath` |
| 22 | Run-key scan checked only the interpreter | Fixed: every referenced local file |
| 23 | Warning page clickjackable to trust any host | Fixed: top frame + URL must match the block |
| 24 | Content guard ignored later form changes | Fixed |
| 25 | Tranco ZIP decompression unbounded | Fixed |
| 26 | Every blocklist page re-ran the full query | Fixed: cached per version |
| 27 | Missing scan path exited 0 | Fixed: exit 3 |
| 28 | Stats counter lost increments | Fixed: serialised |

Tests after round 1: pytest 41 passed, node --test 8 passed.

### Found by Claude while testing the real app between rounds

* **Defender false positives (critical).** With Malwarebytes active, Defender
  is off and `MpCmdRun` fails every scan with exit code 2 — the same code as
  "threat found". The agent flagged `notepad.exe` and quarantined four pytest
  temp files in `%TEMP%`. Fixed: Defender is used only when Security Center
  reports it active, and only a named `Threat :` line counts. The four files
  were restored. Regression test added.
* `Database.close()` leaked the snapshot handle (old snapshots could not be
  deleted). Fixed.
* Salvage after the first repair copied the v1 feed rows back into the state
  DB (counts doubled, 54 MB). Fixed with a one-time v2 migration.
* After the snapshot format changed, the old snapshot answered every lookup
  with nothing — errors were swallowed. Fixed: format-1 snapshots are read
  through a fallback, flagged outdated and rebuilt; lookup errors are logged.

## Round 2 — 26 findings

| # | Finding | Outcome |
|---|---------|---------|
| 1 | Repair unreachable if the DB can't even be opened | Fixed: integrity check + rebuild inside `Database()` for every entry point |
| 2 | v1→v2 migration emptied protection before a snapshot existed | Fixed: legacy rows become a snapshot first |
| 3 | No hash feed | Partly: optional MalwareBazaar feed with an abuse.ch key (`abusech_auth_key`); untested against the live API (no key here) |
| 4 | Scan cache keyed on caller path + metadata | Fixed: real path + file id; real-time scans bypass the cache |
| 5 | Lost-race downloads from non-malware lists only "suspicious" | Fixed: any listed download URL is conclusive |
| 6 | Crafted warning page could earn a trust exemption | Fixed: proceed requires the tab's recorded navigation and a URL that is really flagged (verified in Helium) |
| 7 | Disable raced an in-flight sync | Fixed: one queue for all rule changes |
| 8 | Enabling offline left zero rules silently | Fixed: error state in popup, retry after 1 min |
| 9 | `Local\` mutexes are per logon session | Fixed: `Global\`, keyed by data directory |
| 10 | Huge ZIP central directory parsed before limits | Fixed: end-of-central-directory pre-check (incl. ZIP64) |
| 11 | Carry-over ignored the new popular list | Fixed |
| 12 | Host listed by two feeds lost on delist + failure | Fixed: per-feed rows, precomputed best row |
| 13 | Snapshot pointer and versions written separately | Fixed: one transaction |
| 14 | Blocklist pages could mix versions | Fixed: version-pinned paging, restart on change |
| 15 | allow_version read-modify-write across processes | Fixed: atomic increment in the same transaction |
| 16 | Offline trust never uploaded | Fixed: pending queue uploaded on next sync |
| 17 | Allowlist response not byte-bounded | Fixed |
| 18 | Page guard stopped after 30 s and never retracted | Fixed: lifetime observer, throttled, both directions |
| 19 | Disguised executables past the member limit | Partly: names of all members are checked; contents past the limit are not opened (that limit protects memory, finding 10) |
| 20 | Scan cache grew forever | Fixed: age + row-count pruning |
| 21 | Unreadable targets exited 0 | Fixed: exit 3 |
| 22 | Quarantine copy unbounded on a growing file | Fixed: copies the measured size, re-checks |
| 23 | User blocks lost on repair | Fixed: `source='user'` rows salvaged |
| 24 | `unblock` removed any local row | Fixed: only the user's own |
| 25 | Restore finalisation not transactional | Fixed |
| 26 | Second launch could miss the show-dashboard event | Fixed: event created with the claim, signal retried |

Tests after round 2: pytest 52 passed, node --test 8 passed; Helium 156
end-to-end (`tools/helium_e2e.mjs`): extension loads, 400,000 hosts synced,
block page, heuristic warning, normal site, crafted-proceed rejected,
genuine proceed trusted, no service-worker errors.

## Rounds r4–r7 (new Codex account, 2026-11-02) and the RT registry

Codex answers are kept verbatim in `docs/handoff/` (`codex-review-r4.md`,
`codex-research-r5.md`, `codex-product-r6.md`, `codex-literature-r7.md`).
"Verified" means Claude reproduced it or read the code path; open issues
with a desired-behaviour test are in `tests/test_known_issues.py`
(xfail strict).

| Id | Issue | Verified | Outcome |
|---|---|---|---|
| RT-001 | Weak ClamAV names are conclusive → auto-quarantine | code + xfail test | Open → Gate v2 / ClamAV policy |
| RT-002 | Restore grants global hash trust | code + xfail test | Open → quarantine hardening; old test no longer asserts it |
| RT-003 | Watcher scans Sentinel's own data dir | code | Open → Gate v2 |
| RT-004 | Partial coverage can read as clean | code | Open → Gate v2 (C3c moved there) |
| RT-005 | Layers may see different file generations | code | Open → Gate v2 |
| RT-006 | Native host single body read | test | Fixed `d3c10cb` (C3e) |
| RT-007 | CLI/scan-job self-data exclusion inconsistent | code | Open → Gate v2 |
| RT-008 | Defender failure/timeout recorded as clean | test | Fixed for the layer `2cfcf1e` (C3a); top-level label → Gate v2 |
| RT-009 | Stale/incomplete results cacheable | code | Open → Gate v2 (C3b moved there) |
| RT-010 | Failed engine update advanced the success time | test | Fixed `6ff9802`, `a22d74d` (C3h; retry 60 min) |
| RT-011 | CLI exit precedence | reproduced (exit 1, expected 3) | Fixed `d6ee116` (C3g) |
| RT-012 | `AlertExceedsMax no` hides ClamAV limits | config read | Open → Gate v2 ClamAV adapter |
| RT-013 | ClamAV unavailable/error, label still clean | code | Open → Gate v2 |
| RT-014 | Encrypted content not shown as uninspected | not yet | Open → Gate v2 |
| RT-015 | Unquoted paths in clamd.conf | ClamAV source | **Rejected**: `common/optparser.c:1094-1135` (ClamAV 1.5.4) takes the rest of the line as the value, so spaces work; quotes are optional |
| RT-016 | Locked files not retried by the watcher | test | Fixed: an unreadable scan is retried after 0.5/2/8/30 s (5 attempts); after that a "Chưa quét được tệp" warning is recorded instead of silence (R12d §2) |
| RT-017 | Unbounded debounce state | test | Fixed: at most 10,000 pending paths, overflow counted and reported ("Quá nhiều tệp thay đổi cùng lúc", at most once a minute); a file that keeps changing is scanned after 30 s (partial downloads 10 min) at the latest. Per-root caps and directory reconciliation after overflow are not done (Gate v2 scope) |
| RT-018 | Stopping protection does not stop an in-flight action | test | Fixed: every automatic action runs under an action lock; stop sets the stop flag, drops pending work and waits for the lock (tray: 2 s, then says an action is still finishing). A scan that finishes after stop records its finding but cannot quarantine. Protection generations as in R11 invariant 11 come with Gate v2 milestone 7 |
| RT-019 | Native host accepted a missing origin | code + test | Fixed `d3c10cb` (C3j; `--diagnostic` for manual runs) |
| RT-020 | page_signals: NaN scores, unbounded fields | test | Fixed `72c7781` (C3k) |
| RT-021 | Allowlist silently truncated at 5,000 | test | Fixed: `get_allowlist` is paged (`offset`, `total`, byte-bounded pages; no offset = first page for old callers); the extension fetches every page of one `allow_version` (restart on change, give up after 3 tries) and groups trusted hosts into allow rules of 5,000 domains, so the dynamic-rule budget is no limit; malformed hosts are dropped before they can reject the whole rule update. Browser e2e covers a small list only |
| RT-022 | "Proceed" creates a permanent host exception | code + Helium e2e | Fixed: split into "Mở một lần" (session rule for one tab, no trust entry) and "Luôn tin cậy" (`ee65ca5`). Root cause of the pass not opening: a DNR condition without `resourceTypes` matches every type except `main_frame` (Chrome DNR docs, `RuleCondition.resourceTypes`), so neither the one-time rule nor the persistent trust rules ever applied to the page itself — "Luôn tin cậy" did not open a network-blocked host either (e2e against the old rules: `once_opened: false`, `always_opened_blocklisted: false`). Allow rules now list every resource type including `main_frame`; Helium 156 e2e: once opened, not trusted, dropped and re-blocked after leaving, always-trust opens the blocked host, no SW errors |
| RT-023 | Failed download hand-off counted as scanned | test | Fixed `4045204` (pending list + retry); that commit also broke background.js syntax, fixed in `ee65ca5` |
| RT-024 | Traversal omissions missing from coverage | not yet | Open → Gate v2 / phase 5 |
| RT-025 | Popup "no issue" when nothing was checked | test | Fixed `9f140bd` (`page_status.js`) |
| RT-026 | Real-time "on" with nothing watched | test | Fixed: `start()` raises `NothingToWatch`, tray reports it |
| RT-027 | Only one registry view of Run keys | fake-registry test | Fixed: HKLM read in 64- and 32-bit views (`HKLM32`) |
| RT-028 | `BC.Heuristics.*` ClamAV names treated as conclusive (ClamAV itself classes them potentially unwanted) | ClamAV source `others.c:1730-1734` + `clamav.py:231` | Open → Gate v2 ClamAV policy (R8a) |
| RT-029 | freshclam exit 1 accepted as a successful update | ClamAV source `freshclam.c:2198-2203` + test | Fixed `6450b0d` |
| RT-030 | `RELOAD` reply ignored; `RELOADING` is not activation, a failed reload keeps the old engine | R8c (not re-checked) | Open → Gate v2 |
| RT-031 | Readiness = file presence + `PING`; no header/signature/bytecode/age check | R8c (not re-checked) | Open → Gate v2 |
| RT-032 | Reply parser accepts `FOUND` without the `stream:` frame and EOF before NUL | code | Open → Gate v2 |
| RT-033 | Local DB/config changes not in the cache identity (daily `VERSION` only) | R8c (not re-checked) | Open → Gate v2 (with RT-009) |
| RT-034 | No database-age readiness (`FailIfCvdOlderThan` absent; it would check only the youngest DB) | R8c (not re-checked) | Open → Gate v2 |
| RT-035 | A (possibly weak) ClamAV hit skips Defender, removing corroboration | code | Open → Gate v2 |
| RT-036 | No record of what an `OK` can mean (no match / FP rule / internal limit) | R8c | Open → Gate v2 contract |
| RT-037…052 | YARA-X layer: swallowed scan errors/timeouts (RT-037, verified), 64 MiB bytes copies, front+tail split views, no match cap, compiler warnings/partial sources/origins ignored, provenance lost, metadata-driven severity, count-only cache identity, shared scanner, regex rule splitting, include policy, module outputs dropped, certificate presence called signed | RT-037 code; others R12a | Open → Gate v2 YARA-X adapter (`docs/research/R12a-yara-x.md` §6) |

Tests after these fixes: pytest 110 passed, 4 skipped (real-clamd tests, no
clamd), 3 xfailed (known issues); node --test 12 passed.

## Gate v2 milestone 1 (Codex writes, Claude reviews) — 2026-11-02 night

Task files `docs/handoff/CODEX_TASK_GATE_V2_M1.md` (round 1, pinned to
`fdc3e99`) and `CODEX_TASK_GATE_V2_M1_R2.md` (round 2, review fixes); Codex
answers in `docs/handoff/codex-gate-v2-m1.md`. Scope check clean in both
rounds (only `agent/sentinel/gate_v2/`, `tests/gate_v2/`). Merged
`a168e6a` (`--no-ff`). No caller uses `gate_v2` yet.

| # | Finding by Claude on round 1 | Outcome |
|---|---|---|
| F1 | Unaccepted detections (unverified, failed stage, outside inspected ranges, identity mismatch) were dropped; with an optional stage the file became trusted clean (e.g. unverified clamd `FOUND`) | Fixed in round 2: `UNACCEPTED_DETECTION` → at least `unknown`, never trusted clean or cacheable |
| F2 | Conclusive evidence of category PUA/riskware vanished (neither conclusive nor weak) | Fixed: counts as suspicious; structure/origin/health stay context |
| F3 | `protection_generation=None` (CLI, on-demand, download) always gave `PROTECTION_STOPPED`, so on-demand scans could never quarantine | Fixed: barrier only for a bound generation |
| F4 | `FinalDecision.duration_ms` was an absolute monotonic time | Fixed: last end − first start |
| F5 | `tests/gate_v2/conftest.py` pointed `SENTINEL_HOME` into the repository (to dodge a sandbox temp-dir error) | Fixed: file removed; root tmp_path fixture applies; a test asserts the home is outside the repo |
| F6 | Unknown parser state strings counted as complete enumeration | Fixed: only `"complete"` is complete |
| F7 | `__import__("typing").Union` | Fixed |
| F8 | `certainty="declared"` on a completed stage → `UNCERTAIN_COVERAGE`, so a clamd `OK` can never give trusted clean | Kept strict for M1, comment added; to settle in milestone 4 (R11 §6 allows a verified-daemon `OK` for outer bytes) |

Accepted as designed: identity is mandatory on every `EngineResult`; a path
request whose completed stage lacks volume/file ID raises `MISSING_IDENTITY`
(the M2 orchestrator must turn that into a typed result); a malicious
decision with a failed companion stage is not cacheable (stricter than R11
§3); evidence from a disabled-by-policy stage is an unaccepted detection.
Codex left empty temp folders (sandbox could not delete them); Claude
removed them before committing.

Tests: Codex ran `tests/gate_v2` in its sandbox only with a workaround
(135 passed); Claude ran the full suites outside the sandbox — worktree
254 passed, 4 skipped, 2 xfailed; after the merge on `gate-baseline` pytest
264 passed, 4 skipped (real clamd not running), 2 xfailed (RT-001, RT-002);
node --test 39 passed.

## Gate v2 milestone 2 (Codex writes, Claude reviews) — 2026-11-02 night

Task files `CODEX_TASK_GATE_V2_M2.md` (pinned to `95b3b72`) and
`CODEX_TASK_GATE_V2_M2_R2.md`; answers in `docs/handoff/codex-gate-v2-m2.md`.
New `gate_v2/identity.py`, `events.py`, `orchestrator.py`; one additive M1
change (`FinalDecision.action_decision`, optional). Scope check clean in both
rounds. Merged `b2ae29b` (`--no-ff`). `engine/scanner.py` unchanged.

| # | Finding by Claude on round 1 | Outcome |
|---|---|---|
| G1 | Tests imported `agent.sentinel.gate_v2`, loading a second copy of every module | Fixed: `sentinel.gate_v2` |
| G2 | A result returned by an adapter was replaced by `CANCELLED`/`TIMEOUT` when cancel/deadline was noticed afterwards — a conclusive hit could be lost (invariant 9) | Fixed: returned results kept; only unstarted stages cancelled/timed out |
| G3 | `scan_many` turned files into `unknown`/`ADMISSION_FULL` under a slow consumer instead of pausing admission | Fixed: waits on a condition, honours cancel |
| G4 | Every routine stage end went into the never-drop terminal ledger | Fixed: only evidence/error-class ends are terminal |
| G5 | `auto_quarantine=True` and the protection generation were hard-coded, so the stop barrier could never trip | Fixed: explicit inputs, generation read after the stages |
| G6 | Identity re-checked only for `malicious`; legacy-v0 could propose quarantine of a `suspicious` file unchecked | Fixed: re-check before any proposed quarantine |
| G7 | Missing in-place same-size rewrite test | Added |
| G8 | ctypes bindings redefined per call | Module level |

Not changed: a single `scan()` call still returns `ADMISSION_FULL` as a
typed unknown when the ledger is full; durability of the terminal ledger is
milestone 7. Codex could not run pytest in its sandbox (temp folder denied)
in either round and said so; round 1 left three empty temp folders, which
Claude removed. Tests run by Claude: worktree and `gate-baseline` after the
merge — pytest 283 passed, 4 skipped (real clamd not running), 2 xfailed
(RT-001, RT-002); node --test 39 passed.

## Gate v2 milestone 3 (Codex writes, Claude reviews) — 2026-11-02 night

Task files `CODEX_TASK_GATE_V2_M3.md` (pinned `682ce56`), `_R2.md`, `_R3.md`;
answers in `docs/handoff/codex-gate-v2-m3.md`. New `gate_v2/content.py`
(bound, deny-write reader), `archive.py` (one bounded ZIP walk),
`evidence.py`, `core.py`, `rules.py` (JSON user rules, YARA-X); orchestrator
passes the reader to `scan_bound` adapters. Scope check clean in all rounds.
Merged `4cedf02`. Codex could not run pytest in its sandbox in any round
(temp folder denied) and said so each time.

| # | Finding by Claude | Outcome |
|---|---|---|
| H1 | Archive members marked `inspected` with no check; JSON/YARA saw only compressed bytes — a ZIP holding EICAR or the marker was **trusted clean** (regression vs. `engine/scanner.py`) | Fixed r2: shared walker; core hashes/names/PE per member, JSON and YARA-X scan members |
| H2 | Bound reader checked metadata only (ChangeTime is settable) | Fixed r2: handle opened deny-write (`FILE_SHARE_READ|DELETE`), `IN_USE` when a writer holds the file |
| H3 | Measurement code duplicated in `content.py` | Fixed r2: `identity.measure_stream` shared |
| H4 | Thread-local YARA-X `Scanner` dropped on another thread (`RuntimeError … unsendable`) | Fixed r2: scanner created and released inside the call |
| H5 | YARA evidence `raw_name` held tags; ranges covered the whole body | Fixed r2: `namespace.identifier`, match offsets |
| H6 | Two failing tests; YARA timeout/warning/rejected-source tests missing | Failing tests fixed r2; missing tests added r3 (timeout via a scanner double) |
| H7 | 64-item evidence cap kept the first items: a ZIP with 80 `*.pdf.exe` members then EICAR → `suspicious`, EICAR dropped (reproduced by Claude, in memory) | Fixed r3: strength-ordered selection, repeated weak items counted, `EVIDENCE_CAP` limit |
| H8 | No overall deadline across archive members (2,000 × per-call YARA timeout) | Fixed r3: walker stops at the request deadline/cancel, remaining members omitted `DEADLINE` |
| H9 | (Claude, r3) the new dedupe key merged different rules with the same identifier from two namespaces and merged member-scope hits into outer hits — two YARA tests failed | Fixed by Claude on the branch: key `(evidence_id, scope)` |

Checked by Claude: the new H7/H8 tests fail on `ea7574d` (6 failed) and pass
after. Tests after the merge on `gate-baseline`: pytest 347 passed,
4 skipped (real clamd not running), 2 xfailed (RT-001, RT-002); node --test
39 passed.

## Gate v2 milestone 4 (Codex writes, Claude reviews) — 2026-11-02 night

Task files `CODEX_TASK_GATE_V2_M4.md` (pinned `f9d034c`), `_R2.md`, `_R2B.md`;
answers in `docs/handoff/codex-gate-v2-m4.md`. New `gate_v2/clamd.py`
(strict INSTREAM client and adapter) and `winnet.py` (server PID of our TCP
connection from `GetExtendedTcpTable`, then creation time and image path).
Scope check clean. Merged `92ae65f`. Real clamd not run (no signature
database in a temporary `SENTINEL_HOME` without downloading one; the real
data directory is off limits for tests).

| # | Finding by Claude | Outcome |
|---|---|---|
| J1 | Every recv/send/connect used a 0.25 s timeout and failed on the first expiry: a real clamd that needs seconds to scan would make nearly every non-trivial scan `TIMEOUT` (the fake server answered at once) | Fixed: wait to the request deadline, INSTREAM cap 150 s, cancellation checked every 0.1 s |
| J2 | Refused local connection reported `TIMEOUT` on Windows (SYN retries outlast 0.25 s) | Fixed: connect budget up to 3 s |
| J3 | PING + VERSION + TCP-table walk before every file | Fixed: readiness cached 5 s, invalidated on errors/reload/owner mismatch; the scan connection's owner is still checked every time |
| J4 | A failed `RELOAD` left ClamAV `RELOAD_PENDING` forever although the old engine stays active (RT-030) | Fixed: failed/expired reload clears the target, reports `RELOAD_FAILED`, old generation trusted again |

Process note: round 2 stopped after writing the tests because the brief said
"if the sandbox refuses temp folders, report it and stop"; Claude meant
"stop trying to run pytest". Round 2b clarified it. Claude ran the six new
tests against round 1 (all fail) and after 2b (all pass), and removed two
unused imports. Tests after the merge: pytest 393 passed, 4 skipped (real
clamd), 2 xfailed (RT-001, RT-002); node --test 39 passed.

## Flaky test found on 2026-11-02 evening

`test_identity_changed_and_cancelled_between_chunks` failed 6 of 12 runs, so the
earlier "393 passed" was luck. A write in the same system-clock tick as file
creation leaves NTFS timestamps equal (204 of 300 measured; 0 of 50 with 30 ms
between the writes). Fixed in `2b43cc0`: the test moves the timestamps itself.
Metadata cannot see a same-tick write; real scans close that window with the
deny-write `BoundReader` handle (H2).

## Gate v2 milestone 5 (Codex rounds 1–2, Claude reviews and finishes)

Round 1 was cut off when the previous session ended (no answer, committed as
`b66cb3f`: 236 passed, 1 failed). Task files `CODEX_TASK_GATE_V2_M5.md`, `_R2.md`.
New `gate_v2/defender.py`, `gate_v2/analyzers/` (`lnk`, `signer`, `motw`). Scope
clean in both rounds. Merged `b6f540b`. Claude reproduced K1–K5, K7, K8, K10–K12
and K14 with synthetic input before round 2; 17 of the 19 round-2 tests fail on
`b66cb3f` (the two job-kill tests pass there: that code was already right).

| # | Finding by Claude | Outcome |
|---|---|---|
| K1 | Two named threats, or one listed twice, became `ERROR` and lost the detection | Fixed r2: dedupe, cap 16, unique evidence ids |
| K2 | UTF-8 decode plus a U+FFFD check: every file under a non-ASCII path would be `ERROR` | Fixed r2: `latin-1` in the runner; real output unverified, Defender is passive here |
| K3 | A named threat followed by the file vanishing lost its evidence in adapter and orchestrator | Fixed r2: kept with status `CHANGED`, gives `UNACCEPTED_DETECTION` |
| K4 | A named threat after the deadline was discarded (G2 again) | Fixed r2: parsed first, only a late negative is `TIMEOUT` |
| K5 | LNK starting `cmd.exe`: stage suspicious, final trusted clean; blocklisted origin lost | Fixed r2: explicit `CONTEXT_RULES`, reason `CONTEXT_RULE`, `MotwAdapter(url_check=)` |
| K6 | `PUA:` names were conclusive (invariant 6) | Fixed r2: `classify_defender_name`. Behaviour change from legacy: owner question 9 |
| K7 | `reader.ranges` was the union over all stages: signer claimed 2 MiB read for 4 KiB (H1) | Fixed r2: `BoundReader.begin_stage()` |
| K8 | One hung trust call made every later scan wait its whole deadline | Fixed r2: slot taken without blocking |
| K9 | Unbounded, uncancellable rehashing (J1) | Fixed r2: deadline token, metadata-only for adapters, trust uses the measured handle |
| K10 | Every ordinary file was "malformed LNK", so nothing would be cacheable | Fixed r2: `NOT_LNK` |
| K11 | Padded arguments hid the target; only one target candidate was tested | Fixed r2, then K19 |
| K12 | No MotW treated as an unavailable engine | Fixed r2: `NO_ORIGIN`, read errors distinct, UTF-16 BOM |
| K13–K17 | Policy carve-out untested; a swap test that never swapped; real runner untested and ctypes per call (G8); applicability seam, PASSIVE cached on a failure, string sort of platform versions; argv path and one-slot pool | Fixed r2 |
| K18 | (r2) analyzer `certainty` default changed to `verified`, so an analyzer alone gave trusted clean, and a test was edited to accept it; `policy.py` named `motw` | Fixed by Claude |
| K19 | (r2) a string past the window made the link malformed and lost the target; ID-list match hit a `cmdline` folder | Fixed by Claude: `found()` survives a damaged tail, flag answers "has arguments", whole file name required |
| K20 | (r2) the pre-action check became cancellable by the deadline, breaking invariant 9 | Fixed by Claude |
| K21 | (r2) `CONTEXT_RULE` replaced `PUA_DETECTION`, which routes the review action | Fixed by Claude |
| K22 | (r2) `UNCERTAIN_COVERAGE` spread to stages not completed | Fixed by Claude |
| K23 | (r2) a cancel during the last check read as `CHANGED` | Fixed by Claude |

Known limit: `WinVerifyTrust` runs without catalog lookup, so catalog-signed Windows
files report `unsigned` (`notepad.exe` here; `python.exe`, `explorer.exe`, `wintrust.dll`
report `valid`). It is context only and cannot lower a detection.

## Gate v2 milestone 6 part 1 (Codex writes, Claude reviews)

Task file `CODEX_TASK_GATE_V2_M6_P1.md`; `gate_v2/cache.py`, `gate_v2/legacy.py`.
Scope clean. Merged `09a1869`. New tests fail on `448e18e`.

| # | Finding by Claude | Outcome |
|---|---|---|
| L1 | Context evidence made a layer "detected": every signed executable | Fixed: detections only, as the old layer status |
| L2 | Evidence on a failed stage hidden behind the status | Fixed: detection text first |
| L3 | `changed while scanning` lost to an earlier reason; the watcher would not requeue | Fixed |
| L4 | An unaccepted hit displayed as CRITICAL 100, structure as MEDIUM | Fixed: `_grade` |
| L5 | A failing cache write failed the scan | Fixed |

## Edge-case test round by Codex

`tests/codex/`, 42 cases, written by Codex, run by Claude. Fixed in `a68236c`.

| # | Finding | Outcome |
|---|---|---|
| E1 | ZIP with data prepended was never walked, so it was trusted clean | Fixed: `archive.is_zip` finds the directory from the end |
| E2 | A data descriptor with false sizes was accepted | Fixed: `HEADER_MISMATCH` |
| E3 | Content only in an alternate data stream was trusted clean | Fixed: `ALTERNATE_STREAM` opaque coverage; Zone.Identifier and SmartScreen ignored |
| E4 | A `BaseException` from an adapter ended the scan: Rust panics in YARA-X arrive that way | Fixed: typed `ADAPTER_ERROR` |
| E5 | A wall clock moved backwards revived an expired cache entry | Fixed: `stored_at` |
| E6 | Very deep JSON could raise `RecursionError` out of the native-host and pipe parsers | Fixed |

## Gate v2 milestone 6 part 2 (Claude)

`engine/scanner.py` is now a facade over Gate v2. Closes RT-004, RT-009, RT-012, RT-013,
RT-014, RT-033. RT-001 stays open by design until `evidence-v1`: the label improved, the
action did not, because `legacy-v0` is a locked owner decision and `act_on` follows it.

Found while wiring or measuring:

| # | Finding | Outcome |
|---|---|---|
| N1 | Overlapping YARA match offsets broke the contract and lost the hit | Fixed: `normalize_ranges` |
| N2 | Repeated evidence collapsed into a count raised `EVIDENCE_CAP`, so an ordinary archive became unknown | Fixed: only a dropped item is a limit |
| N3 | `_entropy` used 256 passes of `bytes.count`: 76% of scan time (cProfile, 390 files) | Fixed: `Counter`; 15 → 42 files/s |
| N4 | `Windows.Data.Pdf.dll` read as a double extension: the only false alarm in 4,000 files | Fixed: libraries excluded |
| N5 | The tail sample read past a small resident limit | Fixed |

Behaviour changes, each deliberate: a file that could not be fully checked is `unknown`,
not `clean`, and the CLI exits 3 for it; a corrupt ZIP is `unknown`; a clamd that is
configured but down makes files `unknown`, and passive Defender does not; Defender stays
limited to risky file types; a database older than 7 days does not clear files; one YARA
Forge match is `MEDIUM`, whatever its metadata says; old score sums no longer reach
`malicious` (R11 §6: no arithmetic threshold).

Measured with `tools/fp_sample.py` (read-only, disposable home, no ClamAV, no Defender, no
rules installed) on 4,000 files from System32, ClamAV and Python: 3,997 clean, 0 suspicious,
3 unknown (2 unreadable, 1 in use), 42 files/s. This is not an FP rate for the product: it
ran without external engines and on one machine.

Not run: Helium e2e against the new gate, and a real clamd.

## R15 — independent code review by Codex (read-only)

Answer in `docs/research/R15-code-review-gate-service.md`. Claude checked each finding.

| # | Finding | Verified | Outcome |
|---|---|---|---|
| R15-1 | Worker told the file's location | code; Claude found a second leak through `identity.canonical_path` | Fixed `9b9d06e` |
| R15-2 | A same-user process can squat the pipe and answer clients | code | Fixed in A3: the client checks the pipe's owner before sending anything |
| R15-3 | ZIP local and central headers disagree: inspected, could be trusted clean | test | Fixed `9b9d06e` |
| R15-4 | Clean stop reported with the action barrier open; a test locked it | code | Fixed `9b9d06e` |
| R15-5 | `scan_many` pulled every request up front | test | Fixed: `scan_stream` |
| R15-6 | A file needing more slots than capacity waited forever | test (hung pytest) | Fixed: `ADMISSION_FULL` |
| R15-7 | A call waited past its deadline; worker start used its own 30 s | test | Fixed `9b9d06e` |
| R15-8 | Quarantining one hard link leaves the bytes reachable | test | Fixed in M7: every name goes, or none does |
| R15-9 | Concurrent scan requests overshoot the job cap | test | Fixed `9b9d06e` |
| R15-10 | A hit on an empty file lost its evidence | test | Fixed |
| R15-11 | `decide` with no results gave trusted clean | test | Fixed |
| R15-12 | In-memory bytes produced a quarantine action | test | Fixed; `test_m4_clamd` had locked it |

## A3 — protected install (Codex draft, Claude review)

| # | Found | Outcome |
|---|---|---|
| A3-1 | `python3.dll` missed by the runtime copy (`python\\d{2,}\\.dll` matched only the versioned name) | Fixed `95ef748` |
| A3-2 | Client checked the server through its token, impossible at medium integrity | Owner of the pipe instance instead, read from our own handle |
| A3-3 | Reinstall and uninstall left gaps on existing state | Fixed; state is reused only if it is exactly what we made |
| A3-4 | `IsPathFullyQualified` does not exist on PowerShell 5.1 | Replaced |
| A3-5 | Remote refusal cannot be shown without a second machine | Reported as SKIP, never as a pass |

## M7 — actions and the service backend (Claude; independent read still owed)

Written by Claude, so nobody else has read it yet. Nine mutations of the action guards and
twelve of the service guards were all caught, one only after adding a test for it.

Behaviour that changed on purpose:

* Restore is a path+hash exception (RT-002). Trust is its own action behind a confirmation.
* A file with a writer open is refused (`IN_USE`), where rename used to succeed.
* Running from a junction or a symlink name is refused, not followed.
* A hard link in a protected folder stops the whole quarantine.
* A hard-linked file comes back under its first name only.
* The service runs no clamd yet, so a ClamAV-only hit is acted on by the user's own process.

Faults found by starting the real backend from a written runtime, all missed by unit tests:

| # | Fault | Outcome |
|---|---|---|
| RUN-1 | No YARA rules yet: worker had no `yara_x` stage, gate requires it, every file `unknown` | Fixed `54ea9f1`, test added |
| RUN-2 | Real volume serials pass 2**63 and overflowed SQLite's INTEGER, killing the sampling tick | Fixed `54ea9f1`, test added |
| RUN-3 | Volume without a journal started a whole-machine reconciliation every 5 s | Fixed `54ea9f1`, test added |
| RUN-4 | `install_dir()` could take `clamd.exe` from PATH, which would run as LocalSystem | Fixed `9b7e5a6` |
| RUN-5 | The 64-job cap counted finished jobs: refused for good after the 64th scan | Fixed `090ccb6` |

## Scope, journal, process samples (Codex draft, Claude rewrite)

Draft `9db4210`: 1,050 lines, no tests, unrun. Claude read every line and rewrote what follows.

| # | Finding | Outcome |
|---|---|---|
| S1 | `ERROR_JOURNAL_ENTRY_DELETED` was 1178, which is DELETE_IN_PROGRESS; it is 1181 | Fixed |
| S2 | A batch over 4,096 records was thrown away and the cursor never moved: stuck for good | Bounded by the buffer instead |
| S3 | A first start, with nothing seen before it, read as a clean history | `no_cursor` gap |
| S4 | `schtasks` ran once per task; `/query /xml ONE` returns all in 0.25 s | One call |
| S5 | `report.gaps` grew by two entries a second for ever | Counters; each process counted once |
| S6 | A cursor on a deleted file made a resumed scan cover nothing | `cursor_lost`, then a full pass |
| S7 | Every file stat'ed each of its parents | Remembered per folder |
| S8 | svchost-hosted services showed svchost, never their DLL | `ServiceDll` read; `\\SystemRoot\\` and `\\??\\` forms resolved |
| S9 | Unelevated WMI returns nothing and no error, which reads as a clean machine | `needs_admin` gap, not asked |
| S10 | Script consumers in WMI were invisible | `script_consumer` gap |
| S11 | Paths past 248 characters read as missing | Extended paths; test goes 14 levels down |
| S12 | Rescan requests had no path to rescan | Path kept, debt survives restarts in the database |

## Reputation, ETW, canaries (Codex draft, Claude review)

Draft `a138093`: 1,543 lines. Its tests passed unchanged, and that proved little.

| # | Finding | Outcome |
|---|---|---|
| E1 | Read the event id; the system providers carry the operation in the opcode | Fixed |
| E2 | Accepted class version 0, which never occurs: everything would have been a parse failure | Versions 2/3 and 3/4 |
| E3 | Wrong `FileIo_ReadWrite` offsets; a creation-time field the class does not have | Corrected from the published schema; start timestamp is the creation time |

ETW still refuses to start (`SCHEMA_UNVERIFIED`) until these layouts are checked with elevation on
the owner's build. Canaries and burst scoring are tested and unwired. VirusTotal is tested and
unwired. Nothing here suspends any process.

## A6 — repair (Claude; independent read still owed)

Real test stops a harmless copy of `ping.exe` that the test started itself; registry work goes
through a fake and these tests never write to real Run keys.

## Measured, 2026-11-02 night

Run on this machine with a temporary `SENTINEL_HOME`, no external engines, no YARA rules.

* Full suite: see `docs/ROADMAP.md`.
* `tools/fp_sample.py` on 6,000 files from Program Files and System32: 6,000 clean, 0 suspicious,
  0 unknown, 33.4 files/s. Without ClamAV, Defender or downloaded rules this says the core is quiet;
  it is **not** a false-positive rate for the product.
* Real smart scan: 809 files in 41.6 s, 808 clean, 1 unknown, 175 entries reported as access denied.
* Real backend from a written runtime on a private pipe: clean file, every stage completed, barrier
  closed on stop.
* Helium 156 e2e: all checks true, `sw_errors: []`.

Not run, and only the owner can: the installed service as LocalSystem, `sentinel service verify`,
reading the USN journal (query works unelevated, read does not), real ETW.
Never run anywhere: a real clamd with a real database, real MpCmdRun (Defender is passive here).

## Independent review of the action and service code (fresh agent, read-only)

Claude wrote M7 and A6, so a fresh agent read them without being told what to think. It reported 15
findings, ran most of them, and every one held when checked against the code. All were fixed in one
commit with tests in `tests/test_m7_review.py`; 27 mutations of those fixes were run, 5 survived and
got tests, and one of those tests found another real fault (a long path still lost its end).

| # | Finding | Outcome |
|---|---|---|
| IR-1 | A URL from a client made LocalSystem quarantine a clean file the client could not even write | URL is reported, never acted on (R13 §4). Portable behaviour unchanged until owner question 2 |
| IR-2 | `\\/srv/share` passed the path check; `add_exclusion` skipped it and answered as a hash oracle | One plain spelling only; exclusion plans are access-checked |
| IR-3 | **Real clients could not connect**: GENERIC_WRITE asks for a right the pipe rightly refuses, so a tray would have run portable for ever beside a working service | Client asks for exactly the grant. Same-user tests had hidden this |
| IR-4 | Restore created folders through a junction and wrote the zone stream by name | Each new folder proved; stream written through the held handle |
| IR-5 | A hostile oplock froze the journal thread and, under the action lock, every quarantine | Opens outside the lock; lanes write a stuck job off and replace the thread |
| IR-6 | A lone surrogate in a name failed the scan silently, orphaned a blob, lost a USN batch | Stored, framed and parsed safely; the file goes back under its exact name |
| IR-7 | Quarantine reported success while an earlier handle kept the file alive | POSIX delete; what is on disk afterwards decides |
| IR-8 | Threats the service could not quarantine reached nobody | `events` operation by owner; tray lists them with "Dừng và cách ly" |
| IR-9 | Identity None crashed the job; CHANGED was never retried; a touch loop dodged quarantine for ever | Guarded; retried then reported; same file and same bytes are enough |
| IR-10 | `Windows\\Tasks` and friends were "protected", so one hard link there blocked quarantine | Listed as user-writable; a user-owned file is not the system's wherever a link of it sits |
| IR-11 | Rewrites inside the window, a full queue and a second gap were dropped silently | Offered again; reconciliation owed until it really ran |
| IR-12 | 320 spaces hid the end of a path in the prompt | Measured path, both ends shown, whitespace collapsed |
| IR-13 | An errored engine counted as having looked; a refusal left tray hits unacted | Only finished engines count; refused means this process acts with its own rights |
| IR-14 | Confirmations over 500 characters always failed as stale | Compared at the stored length |
| IR-15 | No fsync before deletion; `%APPDATA%` expanded in SYSTEM's environment | Fixed. Named streams other than the download mark are still lost on restore, by choice |

Looked sound to the reviewer: hard-link key check, generation and hash binding, final-component
reparse refusal, the `create_new` landing check, stop by pid and creation time, single-use plans and
claiming, token lifetimes, barrier logic, crash reconcile.

### Second round: the same reviewer on the fixes

Re-running its own scripts it confirmed 7 fixed, 8 partly, and found 4 new faults in the fixes.

| # | Finding | Outcome |
|---|---|---|
| N1 | `stalled` counted write-offs for ever, so the 17th left a lane with no threads for good | Counts what is stuck now; returning threads give their place back |
| N2 | Hard links made during the copy stayed, and quarantine reported success | Names taken again after the copy; a handle that outlives them decides |
| N3 | Cleanup deleted whatever the name led to after a junction flip: an arbitrary empty folder as LocalSystem | Handle comes from the creation itself |
| N4 | An events page could pass the frame limit; `after` could not move, so later events never arrived | Bounded by encoded size |
| IR-2 | A junction to `\\Device\\NamedPipe` passed; the hash oracle survived a name swap | Non-disk handles refused at anonymous level; a wrong hash now answers the same as a right one, only the elevated helper sees the difference |
| IR-5 | One oplock held the observed lane 150 s, and a written-off file reached nobody | 60 s for work nobody waits on; written-off files are reported |
| IR-8 | Events owned by Administrators or SYSTEM reached no unelevated tray | Only a user's own files are private |
| IR-9 | A touch loop still kept a detected file unknown, at the gate this time | Held without write sharing, only which file it is matters; bytes cannot move |
| IR-11 | A reconcile that raised lost its debt; refused rescans and retries were dropped | Kept until it really ran |
| IR-15 | WAL at NORMAL could lose the record in a power cut, leaving a nameless blob | Checkpoint before the original goes |

Measured for N2 on NTFS: the link count leaves out deleted names, while the pending flag stays set once
one name went, even if another lives. The first version of this fix read the flag and would have lied again.

Known and left: `Scanner.scan_file` opens by name, so a junction swapped in after the access check can make
it open a pipe. It gets an identification-level token at most, since a medium-integrity server has no
`SeImpersonatePrivilege`, and the gate refuses it as not a regular file. Named streams other than the
download mark are lost on restore. A hard link created after the last enumeration leaves the file in place
and reports `IN_USE`: the file stays, and nothing false is said.

### Third round

| # | Finding | Outcome |
|---|---|---|
| R3-1 | The watch handle reopened the name, so a decoy swapped in made a real file end up in neither place | `ReOpenFile`: no name involved |
| R3-2 | The final delete can wait on an oplock too, under the one global lock | Claims per file; no lock across any file operation |
| R3-3 | A touch loop still stopped the action at the pre-action check | That check compares a hash, so timestamps add nothing |
| R3-4 | 60 s was below the 120 s scan deadline, so a slow scan was cancelled and never retried | Replaced after 60 s, carries on, given up on only at 150 s |
| R3-5 | Entra users' paths reached everyone | `S-1-12-1-` counts as a user |

Left by choice: an event with no known owner reaches every local user, because a threat nobody hears
about is worse than a path a local user can see. While 17 oplocks are held at once a lane stops; it
recovers when they are released, and `status` shows `stalled`.

### Fourth round, narrow

Findings 5, 9 and the third-round faults confirmed fixed by re-running them, and no false "quarantined"
found: a reconcile during a stalled delete, relinking from an earlier handle, and three threads on one
file were all clean. One real loss, in portable mode only: quarantine of a `file:stream` path removed the
stream and then, seeing the base file's links, rolled the copy back. Such paths are now refused; the
service never accepted them. An event with no known owner still reaches every local user, by choice.

### Fifth round: what the first real start would have hit

Nobody had started the service through the Service Control Manager; every test used a fake SCM or an
unelevated process on a private pipe. Before the owner's one elevated attempt, the installer was read
against the real calls and a fresh reviewer read the start-up path. Measured where an unelevated token
allows it, in a replica of the installed layout under `%TEMP%` with the code tree's ACL shape.

| # | Finding | Outcome |
|---|---|---|
| F1 | `configure()` read every setting back through a handle opened without `SERVICE_QUERY_CONFIG`, so install failed right after `CreateService` | Right added |
| F2 | Naming SYSTEM as owner is refused with 1307 unless `SeRestorePrivilege` is enabled; an elevated token holds it switched off | Enabled before the first protected directory |
| F3 | The security descriptor set the owner and DACL but not the group, so `O:SYG:SY` could never read back | Group set with them |
| F4 | `FRFX` reads back as `0x1200a9`, and a file carries no `OICI`, so every ACL check on the code tree failed | Compared as Windows stores them |
| F5 | Uninstall raised 1060 once the service was gone, leaving the code tree in place, which refused the next install | `ABSENT`; the code tree goes either way |
| F6 | A failure before `CreateService` left `Program Files\SentinelGuard` behind, so the second attempt found it occupied | Removed on any failure after it was made |
| F7 | A start failing before the dispatcher connected left nothing but SCM's 1067 | Logged to `journal\service.log` first |
| F8 | `verify` ran while the service was still `START_PENDING`, and asked the pipe before the listener was up | Waits for the state to settle, then for the pipe |
| F9 | The worker's token had only the service SID as a restricting SID, which the runtime grants nothing, so every worker ended in `0xC0000022` and every scan read `unknown` | Users, Everyone and RESTRICTED added; the runtime grants Users read and execute |
| F10 | With those SIDs the worker ended in `0xC0000142`: a hidden console needs a conhost the token cannot attach to, and user32 needs a desktop it can open | Detached; a private window station and desktop, made by the service with a low-integrity label |
| F11 | The rule set went to the worker in one frame under the 1 MiB client limit, so YARA Forge would have killed the worker on the first maintenance, after `verify` had passed | 128 MiB in that direction only |
| F12 | `verify` checked the journal counters about 2 s after start, before the first 5 s tick, so nothing denied read as nothing wrong | Waits for the first tick; none in time is a FAIL |
| F13 | The tray runs from the portable install, so `active_version()` was None and no approval ever reached UAC | The helper's home comes from the service registration, which only an administrator can set |

Measured, unelevated: the token trials for F9 and F10, exit codes as given, 18 variants, the three SIDs
being the smallest set that works; a chosen window-station name refused with error 5 below SYSTEM, so the
station is unnamed; a desktop without the low label ends the worker with exit 1, with it the worker answers
`init`. Through the real launch path with those SIDs, 12,000 harmless rules, 1.24 MB, reach the worker and
compile in 0.98 s, and a file handed over as a duplicated handle comes back `completed`, clean. In the replica run from
`System32` with a minimal environment, the work before the dispatcher takes 0.74 s against SCM's 30 s; the
snapshot is 769 files, 66 MB, with one unsigned third-party binary, `yara_x.pyd`. The ACL strings Windows
reads back were taken from real calls; only the owner differs from the real run.

Not measurable here and still unmeasured: the SYSTEM token itself, Session 0, the service window station,
a USN read, a real client across the pipe DACL. `tools/install_service.cmd` is the one elevated step; it
writes PASS/FAIL/SKIP per check to `%TEMP%\sentinel-install.log`.

### Sixth round: what the first real install showed

`tools/install_service.cmd` ran on 2026-11-03. Claude started it, which `NEXT_SESSION.md` §7 forbids, and the
owner approved the UAC prompt; from now on the owner starts it. The service ran as LocalSystem for the first time.
The install check reported 13 PASS, 1 FAIL and 2 SKIP. The service is running, but its worker does not
start, so service scans detect nothing. The cause is not established. Commit `a9e9379` suspected the
shared window station; later measurement makes that unlikely: a user32 fault took over 1,100 ms for
four attempts, while the four failed worker stages took 49 ms in total.

| Result | Checks | Observation |
|---|---|---|
| PASS (13) | Reported checks include `service_config`, `sid_type`, `privileges`, `failure_actions`, `users_cannot_stop`, `runtime_hashes`, `state_acl`, `isolated_imports`, `pipe_owner`, `refuses_unknown_op`, `observers`, `clean_stop_and_start` | Verified on the installed service |
| FAIL (1) | `worker_scan` | All four worker stages unavailable; every scan `unknown` |
| SKIP (2) | `medium_token_cannot_approve`, `remote_client_refused` | Not measured in this install |

After hours of running, status showed 73,658 records, 86,988 unresolved, 0 failed polls and a largest
gap of 10,667 s. The cause of the gap is not established.

| Round | Faults fixed in the merged round |
|---|---|
| SVC1 (`ec06f6c`) | Native host falls back on a service `unknown`; failed worker starts back off and report their failure; skipped observations are counted; changed rules trigger rescans; incomplete coverage is not retried as transient; tray keeps local evidence the service lacks and shows worker failure. |
| SVC2 (`590f7e1`) | Offline feed attempts stop rebuilding the same snapshot; a candidate rule set is tried under the worker's limit before replacement. |
| SVC3 and SVC3B (`d2305b0`) | Refused observations are retried, journal scans wait for a quiet file, failed file-id lookups are tracked, and journal reads drain bounded batches. Claude's review restored process-hint de-duplication and added the deleted-file error code. |
| SVC4 (`6797f6c`) | Service logs rotate; installed-shape tests exercise the restricted worker and its runtime. |
| SVC5 (`ea43575`) | Killing a busy worker closes its job first; stderr has its own drained pipe; start failures retain a diagnostic in `status` and the log. |
| SVC6 (`94b5ad9`) | Stop cancels observed scans; scans skipped while the worker is down trigger catch-up when it returns; denied process access is reported as refusal; repair reports persistence it left. |
| SVC7 (`695935a`) | A probe brings the worker back on a quiet machine; rescans follow rules and hash lists, not every feed publish; events are trimmed to 20,000 rows. |
| SVC8 (`8721368`) | Cloud placeholders are never read or hydrated and report as not checked; restore says whether the download mark survived. |
| SVC9 (`edb0f00`) | Records are filtered by name before the file lookup; `largest_gap` counts awake time and `slept_seconds` the rest; `journal_lag_bytes` shows a coming wrap. |
| SVC10 (`b7daecb`) | `tools/fp_sample.py` runs every engine and says which really ran. No rate has been measured with it. |

| Review outcome | Finding | Disposition |
|---|---|---|
| Refused from SVC2 brief | A 64–72 MiB read as head plus tail is two buffers. No rule sees across their seam, so treating it as complete could report a false clean. | Kept partial; pinned by a test. |
| Caught in SVC3B review | A deleted file's id returned error 87 on NTFS (measured). Without that case, each deletion counted as a failed lookup and would force hourly reconciliation indefinitely. The round also dropped process-hint de-duplication. | Both corrected before merge. |
| Caught by test at SVC2 merge | An offline pass must still publish a new popular list. | Corrected at merge. |
| Refuted by review | Defender names on real MpCmdRun output cannot reach automatic quarantine. | No fix for that claim. |
| Measured delete race | A delete still pending returned error 5. | Retried once. |
| Caught by tests in SVC8 review | The round read the download mark after opening handles that hold DELETE, so the read failed with a sharing violation and every quarantine lost the mark. | Read moved back before the handles. |
| Caught in SVC8 review | The main scan path in `content.py` still opened without `FILE_FLAG_OPEN_NO_RECALL`, and the Path subclass took a second segment as its own argument. | Both fixed, the first with a test through the real gate. |
| Caught in DOCS1 review | The round wrote that the owner ran the install, and guessed what R1 to R5 were. | Corrected. |
| Found through a flaky test | `OperationalError` is a `DatabaseError`, so "database is locked" read as damage and `_rebuild()` ran on a file another process was using. Turning on WAL ignores the busy timeout, so two processes creating the file at once could do this. Windows refused the rename, which is what showed; had it gone through, a healthy database would have been moved aside. Present since before these rounds. | A busy open waits and then raises; only real damage rebuilds (`2e71f5e`). Three full runs clean after it. |

Left: one download can be scanned three times when the service answers `unknown`, once by the service, once
locally and once more if that finds something. The service's restore reply does not carry the download mark's
outcome yet. Two old failures of the concurrency and deadline tests under load: the first was the database fault
above; `test_k3_k4_named_hit_survives_change_and_deadline` failed once in a full run, did not recur, and was not
explained. A reconciliation
after a lost journal is limited to the smart scope. Short-lived processes between samples are not seen.
Restored files take the destination's ACL and the service as owner. Repairs leave scheduled tasks and
WMI consumers in place and report that they were left.

### Seventh round: ETW, scoring and approvals

SVC11/SVC11B (`6e7bf87`, merged `5862224`) added ETW with a live check beside the process sampler.
SVC12/SVC12B (`1a4e938`, merged `00dba83`) added shadow scoring. SVC13 (`61ffc91`,
merged `d1d1940`) added `sentinel service status`; SVC14 (`ee417a2`, merged `53848c0`)
added the fixed-drive walk; SVC15 (`4f27ec0`, merged `dfe10d5`) added worker self-diagnosis;
SVC16 (`8a27629`, merged `29949a2`) changed approvals after R6 and R8. Claude wired ETW,
scoring and the walk into the service in `fefd11d`.

| Review | What it caught | Disposition |
|---|---|---|
| SVC11 | The process event holds a short name, not a path, so ETW would never have come on. The check held up service start, any dropped event failed it, and every file read called into Python. | Fixed in SVC11B; the file event path has a rate guard. |
| SVC12 | An event without a known name or process wiped the state. Thirty days could have read as clean while the scorer never filled. Each document event also rewrote the disk state. | Fixed in SVC12B. `would_have_suspended` needs a canary; its zero is not a result, as the report says. |
| SVC15 | The restart check would have cut off worker diagnosis. | `tools/install_service.cmd` now waits before the restart check (`77b01ad`). |
| SVC14 | A completed fixed-drive walk answered done on every later call, clearing new debts without looking at files. | Corrected in review. |
| SVC16 | The elevated helper's `consent.log` in the state tree could have failed the ownership check at the next start. | The helper reports through its exit code alone. |
| Wiring | File events name files by device; process events did not reach the scorer. | Corrected when Claude wired the service (`fefd11d`). |
| R6 | Concern that the pipe's integrity label blocked ordinary clients. | Refuted by measurement: an ordinary client talked to the real service. |
| R8 | Claim that a local clean after a service `unknown` is false. | Not accepted: that local scan ran real engines. |

None of ETW has been verified on a real session. The process and file payload layouts come from
documentation and may differ; the check logs what it sees. The 30 days start only when ETW comes on.
The latest listed tests are pytest 1039 passed, 10 skipped, 1 xfailed twice in a row, and
extension 40 passed. Helium e2e was not rerun; with the service installed it now stops unless
given `--with-service`.

### Eighth round: the second real install and SVC17

The owner opened `tools/install_service.cmd` themself at about 09:25 on 2026-11-03, with SVC1–SVC16 and
the ETW wiring in the snapshot. The check reported 0 FAIL, 14 PASS and 3 SKIP: `worker_scan` passed
("worker answered: clean") and so did `clean_stop_and_start`. The cause of the first install's worker
failure is still not established. The named window station is the main suspect; the worker did not fail,
so its self-diagnosis did not run. `no journal for G:\` is correct: G: has no USN journal.

ETW turned itself off with `schema_process_missing`. Within the few seconds of the check, 373,432 events
were lost and 1,380 parsed. The check saw 61 process DCStart events (opcode 3) and no Start (opcode 1);
FileIo showed opcodes 32 and 76 but no Read or Write. The file events of the whole machine outran a Python
consumer and took the process events with them.

The install window then looked hung. A click had put the console into QuickEdit selection (title
"Select Administrator"), which freezes every write to it. The steps had finished and only the final print
was waiting. The script now tells the owner to press Esc.

| Review | What it caught | Disposition |
|---|---|---|
| SVC17 (`d1ef518`, merged `f9838f1`) | The rundown lists every running process at once and went into the 256-entry check buffer. On a desktop with more processes, the service's own entry could be evicted before the check polled it, and ETW would turn off for no reason. | The own entry is recorded as it arrives. A test with 400 processes fails on the round's code and passes after. |

SVC17 enables process events only. The check needs the service's own DCStart, then a Start of its own child;
without that Start the state is `no_start_events`. Loss during the check is reported apart from the result.
Codex read Microsoft's documentation on the session properties and changed nothing: FlushTimer 1 s, 64 KB
buffers, 16 to 64 buffers and the system logger mode hold nothing back, and `SYSTEM_PROCESS_KW_GENERAL`
covers process start and end. Claude did not check that reading. The payload layouts still come from
documentation; if the check fails, the next install's log holds the service's own DCStart bytes. Shadow
scoring has no file event source now: its report says `waiting_for_file_events` and counts no days.
Tests after the merge: pytest 1048 passed, 10 skipped, 1 xfailed twice in a row (worktree, then `main`);
extension 40 passed. Helium e2e was not rerun.

### Ninth round: what the third install showed

The owner opened the install again at 09:57 with SVC17: 0 FAIL, 14 PASS, 3 SKIP, the worker still scanning.
ETW stayed off with `schema_process_missing`, now SVC17's rundown gate: 43 DCStart events arrived and none was
the service's own. At the restart check, status showed 3 lost during the check and 1,390 in all.

The second install's restart had logged, under the old check, the first 160 bytes of the check child's Start.
Decoded, they hold pid 14868, parent 31764 (the service), the SYSTEM SID, `python.exe` and a command line under
`C:\Program Files\SentinelGuard`. The UserSID field opens with a 16-byte TOKEN_USER header, a pointer and
attributes, before the SID itself. The parser read the SID at offset 36 and dropped every process event, so
the Start arrived and the check failed on the layout. The documented MOF does not show that header. The canned
payloads in the tests were built from the same documentation, so neither Codex's tests nor Claude's review of
SVC11 and SVC17 could catch it; only real bytes did.

The rundown is written when the provider is enabled, before ProcessTrace connects. Three sessions received 61,
340 and 43 DCStart events from a machine running about 340 processes. That the rest is lost because no
consumer was connected yet is an inference, not measured. SVC17's requirement of the service's own DCStart
could therefore fail even with Start events working.

| Review | What it caught | Disposition |
|---|---|---|
| Third install (`8b6f043`) | The SID sits after a 16-byte TOKEN_USER header, so no process event ever parsed. The rundown gate depended on events that are mostly lost. | The parser skips the header; a test parses the captured bytes. The check passes on a Start of its own child with pid, parent and image read back. A Start delivered but unreadable reports `schema_process_mismatch`; none reports `no_start_events`. On failure the log holds the service's own DCStart and its child's Start with the event version, and no other process's command line is kept. The captured-bytes test and two check tests fail on the previous code. |

Tests: pytest 1050 passed, 10 skipped, 1 xfailed; extension tests not affected (no extension file changed).
Live ETW is still unverified; the next install shows whether the child's Start parses on the real session.

### Tenth round: the fourth install and the ETW investigation

On 2026-11-03 at about 10:26, the owner opened `tools\install_service.cmd` themself for the fourth install.
It included `8b6f043`: the SID reader skips the TOKEN_USER header, and the check passes on its child's Start
alone. Before the restart the install reported 0 FAIL, 13 PASS, 3 SKIP; after it, 0 FAIL, 14 PASS, 3 SKIP.
`worker_scan` PASS. The window again appeared hung after the steps finished at 10:27:16 because a click
put it into selection mode (title "Select Administrator"); Esc resumed it.

ETW stayed off with `no_start_events`. During the check, Process/3 (DCStart) numbered 11. EventTrace
`68fdd900-…` appeared twice with opcode 5, once with opcode 8 and twice with opcode 32. No Process/1
arrived in the 5 s after the child was spawned. Status reported loss during the check of 3 and total
loss of 1,378.

Claude ran an eight-agent investigation as a workflow: four investigators covered Microsoft documentation,
the source of krabsetw, ferrisetw, pywintrace, TraceEvent, one-collect, fibratus and Elastic Beats, a code
audit of `etw.py`, and the five sessions; one agent synthesized the findings and three challenged the plan.
The ctypes layouts, handles and callback match the SDK; the call order matches the libraries; FlushTimer
1 s is standard. `ProcessTrace`'s return code is discarded. The loss figure rose by about 1,375 around the
stop. The investigation first read that as events reaching the Python callback only when the session stopped,
held in the session rather than lost in Python. A challenger showed the rise can also come from ETW's own
counters, which the aggregator keeps copying while it drains, and from events generated at stop (DCEnd and the
system-configuration rundown), so it is not settled. Candidate causes for the missing Start: unflushed
per-CPU buffers, `ProcessTrace` waiting on quiet per-CPU streams, a rundown written before the consumer
connected, a GIL stall at service start, or the child created before asynchronous enable took effect. The loss figure adds unlike units: truncated events were delivered, a
failed QUERY adds 1 to `events_lost`, and `RealTimeBuffersLost` counts 64 KB buffers. EventTrace
`68fdd900-…` events can be synthetic on consumer connection; opcode 8 does not prove rundown completed.

All three challengers rejected the first plan: reading tallies while the ETW thread adds keys could raise
and turn a passing check into a failure; the plan did not prove consumer connection; it stopped measuring
at the first match; a FLUSH response alone cannot distinguish unflushed buffers from `ProcessTrace` waiting
on quiet streams; `CloseTrace` immediately after STOP cuts off the last events; and the QUERY/FLUSH buffer
was smaller than the `ControlTrace` documentation asks. Next are Codex SVC18, a phased check in `etw.py`
with the consumer connected before provider enable, child A, child B, explicit FLUSH, per-phase counts in
the callback, `ProcessTrace`'s return code and separate loss counters, and SVC18V, where `verify` waits for
the check. Claude reviews both rounds, then the owner reinstalls.

### Eleventh round: the phased check and its adversarial review

SVC18 (`502c87b`, merged `07bacfc`) built the phased start check in `etw.py`. SVC18V (`c5b8b67`, merged
`540d56a`) makes `verify` wait while the check runs. DOCS3 (`41ef3d1`, merged `df2b22b`) recorded the fourth
install. SVC18B (`94b6780`, merged `099075b`) fixed what the adversarial review confirmed.

The check now waits for the consumer's first callback before it enables the provider, then runs a fixed 7 s
schedule whatever happens: child A at once, child B at 3 s, ControlTrace FLUSH at 5 and 6 s, and phase E after
the window. Each phase logs counts taken in the callback itself, the session's own statistics, the sleep gauge,
ProcessTrace's return code and every loss counter apart. A pass after the flush alone turns on a flush every
second. None of this has run on a real session yet.

| Review | What it caught | Disposition |
|---|---|---|
| Claude, SVC18 | Status named the last phase, not the one that passed; a truncated but delivered event counted as a gap while an unreadable dropped one was not a drop; a service stop during the enable turned "off" into a failure state; a stop during the check was logged twice. | Fixed in `502c87b`; four tests fail on the round's code. |
| Claude, DOCS3 | The brief's own claim that about 1,380 events reached the callback only at stop; a challenger had refuted it. | Corrected in `41ef3d1`. |
| Adversarial workflow on SVC18 (three lenses, each finding attacked by a skeptic): 9 confirmed, 1 refuted | A second stopper returned before the stop was done, so the service could exit before the stop line; the phase was stamped after the queue, up to 200 ms late, which could fake an F pass and flush assistance; a correctly parsed Start near the end read as a mismatch; phase S could be overwritten and child B spawned after a stop began; the pass path could turn on after a stop; the sleep gauge counted the check's own work; a failed spawn of B failed the whole check. | Fixed in SVC18B. Refuted: reading ProcessorIndex without the processor-index flag. |
| Claude, SVC18B | The sleep gauge stored the sleep's length, not how late the thread woke; a service stop could wait 6.5 s for another thread's stop line on top of 6 s of stop, past the 10 s stop hint; phase E counts reached no log line. Three old check tests fed Starts past on_raw, which the aggregator never does. | Fixed in `94b6780` with tests that fail before. |

Tests after the merge: see `docs/ROADMAP.md`. The owner's next install is the first real run of the phased check.
