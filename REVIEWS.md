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
| RT-016 | Locked files not retried by the watcher | not yet | Open → phase 5 |
| RT-017 | Unbounded debounce state | not yet | Open → phase 5 |
| RT-018 | Stopping protection does not stop an in-flight action | not yet | Open → phase 5 |
| RT-019 | Native host accepted a missing origin | code + test | Fixed `5af59ed` (C3j; `--diagnostic` for manual runs) |
| RT-020 | page_signals: NaN scores, unbounded fields | test | Fixed `62ff720` (C3k) |
| RT-021 | Allowlist silently truncated at 5,000 | not yet | Open → phase 5 |
| RT-022 | "Proceed" creates a permanent host exception | code | Open → phase 5 |
| RT-023 | Failed download hand-off counted as scanned | code | Open → phase 5 |
| RT-024 | Traversal omissions missing from coverage | not yet | Open → Gate v2 / phase 5 |
| RT-025 | Popup "no issue" when nothing was checked | not yet | Open → phase 5 |
| RT-026 | Real-time "on" with nothing watched | test | Fixed: `start()` raises `NothingToWatch`, tray reports it |
| RT-027 | Only one registry view of Run keys | fake-registry test | Fixed: HKLM read in 64- and 32-bit views (`HKLM32`) |
| RT-028 | `BC.Heuristics.*` ClamAV names treated as conclusive (ClamAV itself classes them potentially unwanted) | ClamAV source `others.c:1730-1734` + `clamav.py:231` | Open → Gate v2 ClamAV policy (R8a) |

Tests after these fixes: pytest 110 passed, 4 skipped (real-clamd tests, no
clamd), 3 xfailed (known issues); node --test 12 passed.
