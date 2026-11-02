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
| RT-006 | Native host single body read | test | Fixed `5af59ed` (C3e) |
| RT-007 | CLI/scan-job self-data exclusion inconsistent | code | Open → Gate v2 |
| RT-008 | Defender failure/timeout recorded as clean | test | Fixed for the layer `d77dea1` (C3a); top-level label → Gate v2 |
| RT-009 | Stale/incomplete results cacheable | code | Open → Gate v2 (C3b moved there) |
| RT-010 | Failed engine update advanced the success time | test | Fixed `754b745`, `c3714fd` (C3h; retry 60 min) |
| RT-011 | CLI exit precedence | reproduced (exit 1, expected 3) | Fixed `290f4a0` (C3g) |
| RT-012 | `AlertExceedsMax no` hides ClamAV limits | config read | Open → Gate v2 ClamAV adapter |
| RT-013 | ClamAV unavailable/error, label still clean | code | Open → Gate v2 |
| RT-014 | Encrypted content not shown as uninspected | not yet | Open → Gate v2 |
| RT-015 | Unquoted paths in clamd.conf | ClamAV source | **Rejected**: `common/optparser.c:1094-1135` (ClamAV 1.5.4) takes the rest of the line as the value, so spaces work; quotes are optional |
| RT-016 | Locked files not retried by the watcher | test | Fixed: an unreadable scan is retried after 0.5/2/8/30 s (5 attempts); after that a "Chưa quét được tệp" warning is recorded instead of silence (R12d §2) |
| RT-017 | Unbounded debounce state | test | Fixed: at most 10,000 pending paths, overflow counted and reported ("Quá nhiều tệp thay đổi cùng lúc", at most once a minute); a file that keeps changing is scanned after 30 s (partial downloads 10 min) at the latest. Per-root caps and directory reconciliation after overflow are not done (Gate v2 scope) |
| RT-018 | Stopping protection does not stop an in-flight action | test | Fixed: every automatic action runs under an action lock; stop sets the stop flag, drops pending work and waits for the lock (tray: 2 s, then says an action is still finishing). A scan that finishes after stop records its finding but cannot quarantine. Protection generations as in R11 invariant 11 come with Gate v2 milestone 7 |
| RT-019 | Native host accepted a missing origin | code + test | Fixed `5af59ed` (C3j; `--diagnostic` for manual runs) |
| RT-020 | page_signals: NaN scores, unbounded fields | test | Fixed `62ff720` (C3k) |
| RT-021 | Allowlist silently truncated at 5,000 | test | Fixed: `get_allowlist` is paged (`offset`, `total`, byte-bounded pages; no offset = first page for old callers); the extension fetches every page of one `allow_version` (restart on change, give up after 3 tries) and groups trusted hosts into allow rules of 5,000 domains, so the dynamic-rule budget is no limit; malformed hosts are dropped before they can reject the whole rule update. Browser e2e covers a small list only |
| RT-022 | "Proceed" creates a permanent host exception | code + Helium e2e | Fixed: split into "Mở một lần" (session rule for one tab, no trust entry) and "Luôn tin cậy" (`d422f74`). Root cause of the pass not opening: a DNR condition without `resourceTypes` matches every type except `main_frame` (Chrome DNR docs, `RuleCondition.resourceTypes`), so neither the one-time rule nor the persistent trust rules ever applied to the page itself — "Luôn tin cậy" did not open a network-blocked host either (e2e against the old rules: `once_opened: false`, `always_opened_blocklisted: false`). Allow rules now list every resource type including `main_frame`; Helium 156 e2e: once opened, not trusted, dropped and re-blocked after leaving, always-trust opens the blocked host, no SW errors |
| RT-023 | Failed download hand-off counted as scanned | test | Fixed `0a29a6e` (pending list + retry); that commit also broke background.js syntax, fixed in `d422f74` |
| RT-024 | Traversal omissions missing from coverage | not yet | Open → Gate v2 / phase 5 |
| RT-025 | Popup "no issue" when nothing was checked | test | Fixed `fcb74d5` (`page_status.js`) |
| RT-026 | Real-time "on" with nothing watched | test | Fixed: `start()` raises `NothingToWatch`, tray reports it |
| RT-027 | Only one registry view of Run keys | fake-registry test | Fixed: HKLM read in 64- and 32-bit views (`HKLM32`) |
| RT-028 | `BC.Heuristics.*` ClamAV names treated as conclusive (ClamAV itself classes them potentially unwanted) | ClamAV source `others.c:1730-1734` + `clamav.py:231` | Open → Gate v2 ClamAV policy (R8a) |
| RT-029 | freshclam exit 1 accepted as a successful update | ClamAV source `freshclam.c:2198-2203` + test | Fixed `5454a46` |
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
`682a495`) and `CODEX_TASK_GATE_V2_M1_R2.md` (round 2, review fixes); Codex
answers in `docs/handoff/codex-gate-v2-m1.md`. Scope check clean in both
rounds (only `agent/sentinel/gate_v2/`, `tests/gate_v2/`). Merged
`9a101cb` (`--no-ff`). No caller uses `gate_v2` yet.

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

Task files `CODEX_TASK_GATE_V2_M2.md` (pinned to `8d95a1d`) and
`CODEX_TASK_GATE_V2_M2_R2.md`; answers in `docs/handoff/codex-gate-v2-m2.md`.
New `gate_v2/identity.py`, `events.py`, `orchestrator.py`; one additive M1
change (`FinalDecision.action_decision`, optional). Scope check clean in both
rounds. Merged `e186184` (`--no-ff`). `engine/scanner.py` unchanged.

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

Task files `CODEX_TASK_GATE_V2_M3.md` (pinned `fe2949d`), `_R2.md`, `_R3.md`;
answers in `docs/handoff/codex-gate-v2-m3.md`. New `gate_v2/content.py`
(bound, deny-write reader), `archive.py` (one bounded ZIP walk),
`evidence.py`, `core.py`, `rules.py` (JSON user rules, YARA-X); orchestrator
passes the reader to `scan_bound` adapters. Scope check clean in all rounds.
Merged `7226927`. Codex could not run pytest in its sandbox in any round
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

Checked by Claude: the new H7/H8 tests fail on `6f9618d` (6 failed) and pass
after. Tests after the merge on `gate-baseline`: pytest 347 passed,
4 skipped (real clamd not running), 2 xfailed (RT-001, RT-002); node --test
39 passed.

## Gate v2 milestone 4 (Codex writes, Claude reviews) — 2026-11-02 night

Task files `CODEX_TASK_GATE_V2_M4.md` (pinned `18454a9`), `_R2.md`, `_R2B.md`;
answers in `docs/handoff/codex-gate-v2-m4.md`. New `gate_v2/clamd.py`
(strict INSTREAM client and adapter) and `winnet.py` (server PID of our TCP
connection from `GetExtendedTcpTable`, then creation time and image path).
Scope check clean. Merged `fe2880b`. Real clamd not run (no signature
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
