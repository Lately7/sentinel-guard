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
