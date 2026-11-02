# Codex product review — round 6 (read-only, web search, dashboard screenshot attached)

Prompt: `docs/handoff/PROMPT_CODEX_PRODUCT.md`, 2026-11-02, reviewed commit f02b5d2.
Claude verified against the code: RT-019 (nativehost.py:220 accepts a missing origin),
RT-022 (background.js:364 `trust()` persists the host), RT-023 (background.js:249 counts the
download before the request and swallows the error), RT-026 (watcher.py:263 sets running=True
regardless of watched dirs) are confirmed. The others are not yet reproduced. The logo critique
refers to the procedural v1 logo, since replaced. External claims are Codex's, with its sources.

## Codex answer (verbatim)

# Sentinel Guard product and logic review

Read-only static review. I did not run the test suites because they can create caches/reports, and the request prohibited creating files. No repository files were modified; `git status --short` remained empty.

## Executive assessment

All three required product features exist, but their present scope is narrower than their labels suggest:

- On-demand scanning is a multi-engine file/folder walker. “Quick scan” currently means the configured watched directories, not the locked smart-scan design. There is no distinct Deep Scan.
- Browser protection is the strongest, most differentiated feature: local blocklists, MV3 network rules, per-navigation agent lookup, page heuristics, and completed-download scanning. Its weakest points are durable exceptions and silent native-handoff failures.
- Real-time protection is post-write monitoring. It can scan and quarantine after a filesystem event, but it cannot reliably stop a file before execution.

The highest-priority product work remains Contract v1, honest coverage reporting, quarantine-policy separation, and stable file/engine identity. That is consistent with locked sections 7 and 11.

# Part 1 — Logic as built

## 1. On-demand Scan

| Stage | Current path |
|---|---|
| Entry | File, folder, Quick, and Full buttons call `GatePanel.run()` (`agent/sentinel/gate_ui.py:154-181`). Quick uses only existing `settings.watch_dirs` (`agent/sentinel/tray.py:201-203`). Full enumerates fixed drives (`agent/sentinel/scanjob.py:26-39`). |
| Enumeration | `ScanJob` walks files, skips junction/symlink directories and an exact Sentinel-data path, and supports cancellation between files (`agent/sentinel/scanjob.py:42-77,129-145`). |
| Engines | `Scanner.scan_file()` resolves the path, hashes the measured bytes, consults cache/allowlist, then runs Sentinel signatures/name/type/PE/ZIP checks, rule packs/YARA-X, ClamAV, and conditionally Defender (`agent/sentinel/engine/scanner.py:61-145,161-210,228-298`). |
| Verdict | Findings are deduplicated by rule score; one critical finding or aggregate score ≥70 becomes malicious, ≥30 suspicious (`agent/sentinel/engine/verdict.py:52-72`). |
| Action | Suspicious results are logged; malicious results are automatically quarantined when enabled (`agent/sentinel/protection.py:23-42`, `agent/sentinel/quarantine.py:64-97`). |
| UI/log | Progress and non-clean results reach the table; completion creates a scan event with counts (`agent/sentinel/scanjob.py:146-167`, `agent/sentinel/gate_ui.py:194-244`). |

It does **not** currently:

- Implement the locked smart scope: Startup entries, both Run-key registry views, Task Scheduler actions, and running process images are absent.
- Have a separate Deep Scan.
- Scan process memory, behavior, kernel objects, boot sectors, or cloud reputation.
- Interrupt an active file scan promptly on cancellation.
- Prove complete coverage when an engine fails or hits an internal limit; that remains RT-004/RT-012/RT-013/RT-014.
- Record clean, skipped, and unreadable files individually in the result table.

## 2. Helium browser protection

| Stage | Current path |
|---|---|
| Entry | MV3 service worker with DNR, navigation, downloads, storage, notification, and native-messaging permissions (`extension/manifest.json:8-23`). |
| Network blocklist | The agent pages up to 400,000 blocked hosts; the extension turns them into main-frame redirects and subresource blocks (`agent/sentinel/nativehost.py:101-132`, `extension/src/background.js:74-155`, `extension/src/rules.js:9-58`). |
| Navigation | Every top-frame HTTP(S) navigation is scored locally and, when possible, checked against the agent’s exact URL/parent-host intelligence (`extension/src/background.js:178-210`, `agent/sentinel/urlintel.py:94-115`). |
| Page signals | A content script inspects password forms, HTTP login pages, cross-domain actions, and unusually bare login pages (`extension/src/content/page_guard.js:14-40`). Its message is checked in the service worker before privileged work (`extension/src/background.js:269-343`). |
| Warning/action | Known-malicious or high-scoring navigation goes to `blocked.html`; proceeding adds the host to the persistent allowlist (`extension/src/blocked.js:22-46`, `extension/src/background.js:301-327,364-385`). |
| Downloads | Malicious source URLs trigger a cancel attempt. Completed files are sent by absolute path to the native host, rescanned through `Scanner`, and possibly quarantined (`extension/src/background.js:220-263`, `agent/sentinel/nativehost.py:134-150`). |
| UI/log | Popup shows agent state, rule count, current-page status, statistics, and trust/sync actions. Web/download events are recorded through `on_report()` and `act_on()` (`extension/src/popup.js:4-78`, `agent/sentinel/nativehost.py:152-175`). |

It does **not** currently:

- Supply cloud URL/file reputation, signer/download prevalence, or a large commercial telemetry loop.
- Guarantee every completed download reaches the agent; failures are silently discarded.
- Provide a one-navigation bypass: “proceed” persistently trusts the host.
- Mark search results, block ads/trackers, or analyze arbitrary page content beyond a small password-form heuristic set.
- Inspect a file before a browser makes it available.
- Protect when the extension is disabled, the native host is disconnected, or rule synchronization fails.

## 3. Real-time protection

| Stage | Current path |
|---|---|
| Entry | Tray startup creates `RealtimeProtection` when enabled (`agent/sentinel/tray.py:66-85,118-126`). |
| Triggers | Watchdog submits file create, modify, and move-destination events recursively. Run/RunOnce entries are polled every 15 seconds (`agent/sentinel/watcher.py:104-166,218-249`). |
| Debounce | Normal paths settle for 1.5 seconds; partial-download suffixes wait 90 seconds. A 300 ms size check precedes scanning (`agent/sentinel/watcher.py:20-28,53-101`). |
| Engines/verdict | The same `Scanner` and verdict path as on-demand scanning is used, with scan cache disabled (`agent/sentinel/watcher.py:82-99`). |
| Action/UI | `act_on()` logs and may quarantine. The tray notifier displays non-info events and turns the icon red for threats (`agent/sentinel/protection.py:23-42`, `agent/sentinel/tray.py:142-151`). |

It does **not** currently:

- Hold a filesystem open, block execution, or scan before access.
- Attribute a write to a process.
- Observe process memory, exploit behavior, ransomware behavior, drivers, or protected kernel activity.
- Guarantee coverage while Sentinel is stopped or an event is missed.
- Monitor both 32- and 64-bit Run-key views.
- Retry all transiently locked/unreadable files.

## README claims that overstate delivery

- “Every file passes through all layers” (`README.md:16`) is false for allowed hashes, non-risky Defender skips, already-malicious files, unavailable engines, and oversized/partial files.
- “Clean is never confused with nobody checked” (`README.md:25-26`) is contradicted by RT-004 and RT-013: the top-level label still derives only from findings.
- “The exact bytes the agent hashed” reach ClamAV (`README.md:27-28`) is only reliable for in-memory files. Large files are reopened, and Defender scans the pathname later: RT-005.
- The YARA statement (`README.md:21`) reads like installed coverage, but YARA Forge is optional and the handoff says the real rules directory is empty.
- Per-navigation browser lookup (`README.md:44-45`) is unavailable when the native agent is disconnected.
- Run-key monitoring (`README.md:30-32`) omits that only the process-default registry view is read.

# Part 2 — Mainstream-product comparison

## A. Scan modes

| Product | Documented structure | Difference from Sentinel |
|---|---|---|
| Microsoft Defender | Quick scans startup registration locations and also checks processes, memory, profiles, and selected system locations. Full begins with Quick and scans mounted fixed disks, with removable/network drives configurable. Custom scans selected files/folders. Offline Scan restarts into Windows Recovery Environment. [Microsoft scan-mode documentation](https://learn.microsoft.com/en-us/defender-endpoint/schedule-antivirus-scans) | Sentinel Quick currently walks watched directories only; Full is fixed-drive traversal; it has no memory/process/registry smart enumeration or offline mode. |
| Bitdefender | Quick Scan uses cloud-assisted checks for threats running in the system; System Scan performs a thorough whole-system scan; Custom Scan selects files, folders, or drives and exposes priority/application-only options. [Bitdefender scan guide](https://www.bitdefender.com/consumer/support/answer/1477/), [custom scan options](https://www.bitdefender.com/consumer/support/answer/2056/) | Sentinel runs essentially the same local pipeline for every scope and lacks cloud classification and a separately tuned quick/deep engine policy. |
| Malwarebytes | Quick checks memory and startup programs; Threat Scan targets common system locations/files/programs; Custom selects scope and items; Deep Scan uses the most comprehensive database and advanced detection and is recommended after a detection. [Malwarebytes scan types](https://help.malwarebytes.com/hc/en-us/articles/31589479207579-Scan-types-in-Malwarebytes-for-Windows-and-Mac) | Sentinel’s Quick is closer to a limited Custom Scan. It has no current Threat/Smart scope or Deep mode. |

Documented fact: these vendors distinguish scan modes by both **scope** and sometimes **detection policy**.  
Inference: Sentinel should not create four labels around the same directory walker. “Scan” and “Deep Scan” need visibly different scope, budgets, and coverage reporting.

## B. Real-time triggers

| Product | Documented structure | Difference from Sentinel |
|---|---|---|
| Microsoft Defender | On-access scanning covers incoming/outgoing file and program activity, with behavior monitoring, heuristics, memory scanning, and cloud-delivered protection. Microsoft describes on-access triggers including open, read, write, and modify. [Always-on protection](https://learn.microsoft.com/en-us/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus), [scan triggers](https://learn.microsoft.com/en-us/defender-endpoint/configure-extension-file-exclusions-microsoft-defender-antivirus) | Sentinel receives post-operation directory notifications and cannot hold the operation or process launch. |
| Bitdefender | Shield scans accessed files and received email; configurable signals include applications, scripts, shares, and PUAs. Advanced Threat Defense separately monitors and correlates running-process behavior. [Bitdefender Shield](https://www.bitdefender.com/consumer/support/answer/13450/), [Advanced Threat Defense](https://www.bitdefender.com/consumer/support/answer/2024/) | Sentinel has static file analysis only and no runtime behavior correlation. |
| Malwarebytes | Malware Protection monitors and prevents malicious files/programs from launching; Exploit and Ransomware Protection are separate behavioral layers. [Malwarebytes real-time layers](https://help.malwarebytes.com/hc/en-us/articles/31589448817563-Turn-on-Real-Time-Protection-in-Malwarebytes-for-Windows-and-Mac) | Sentinel cannot make an equivalent “prevents launch” claim. |

Inference: mainstream prevention depends on native/privileged observation points. Microsoft identifies anti-malware as a canonical filesystem-minifilter use. An ordinary user-mode Python watcher cannot reproduce that guarantee. [Microsoft minifilter architecture](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers)

## C. Browser protection signals

| Product | Documented signals |
|---|---|
| Sentinel | Local domain/URL feeds, DNR network blocking, structural URL scoring, a small password-form heuristic set, source-URL inheritance, and completed-file scanning. No cloud reputation. |
| Malwarebytes Browser Guard | Malware/scam/phishing/PUP and suspicious-download protection, ads/trackers, skimmer protection, reputation and block pages. Its “Continue anyway” flow can be temporary unless the user explicitly chooses not to block the site again. [Browser Guard features](https://www.malwarebytes.com/solutions/safe-browser), [block-page behavior](https://help.malwarebytes.com/hc/en-us/articles/31589238609563-Types-of-block-pages-caused-by-Browser-Guard) |
| Bitdefender TrafficLight | Cloud-assisted checks of visited pages for malware/phishing, malicious-element filtering, link/search-result marking, and tracker identification. [TrafficLight product page](https://www.bitdefender.com/en-us/consumer/trafficlight), [current extension description](https://chromewebstore.google.com/detail/trafficlight/cfnpidifppmenkapgihekkeednfoenal) |
| Google Safe Browsing | Canonicalizes URLs and checks local or real-time hash-prefix/full-hash threat data for malware, social engineering, and unwanted software. Chrome Enhanced Protection additionally uses real-time URLs, limited page features, extension/system data, and optional suspicious-file submission. [Safe Browsing v5](https://developers.google.com/safe-browsing/reference), [Chrome Enhanced Protection](https://support.google.com/chrome/answer/13844634?hl=en) |
| Microsoft SmartScreen | Uses dynamic URL/site intelligence and page analysis; downloaded-app checks incorporate file hash, publisher signature, download prevalence/history, past antivirus results, and URL reputation. [SmartScreen for Edge](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-security-smartscreen), [application reputation](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation) |

Inference: Sentinel’s local design has privacy and offline benefits, but it has a larger freshness gap and cannot determine that a novel signed/unsigned download is rare, prevalent, or previously observed as safe.

# Part 3 — New defects and weaknesses

Related existing issues are not renumbered: RT-003 covers Sentinel-data watching, RT-004/012/013/014 cover false-clean and incomplete coverage, RT-005 covers mixed file generations, RT-006 covers native short reads, and RT-007 covers noncanonical/self-data traversal.

The tests below are proposed and were not run.

### RT-016 — Transiently locked files are not retried — High

- **Location:** `agent/sentinel/watcher.py:82-101`; `agent/sentinel/engine/scanner.py:64-76`
- **Reproduction:** Use a harmless file opened without sharing, or a fake scanner that first returns `skipped="unreadable: sharing violation"` and succeeds on the second call. The watcher sends the unreadable result through `act_on()` and does not resubmit it.
- **Proof test:** `test_watcher_retries_transient_unreadable_file`
- **Direction:** Classify sharing/lock/access failures as retryable with bounded exponential backoff and a final visible `coverage=unreadable` event.

### RT-017 — Debounce state is unbounded — Medium

- **Location:** `agent/sentinel/watcher.py:40,53-71`
- **Reproduction:** Submit many harmless unique nonexistent paths; every path remains in `_pending` until due.
- **Proof test:** `test_scan_queue_is_bounded_under_unique_path_storm`
- **Direction:** Bound pending paths/events, coalesce by canonical path, expose overflow counts, and schedule a recovery scan after overflow.

### RT-018 — Turning protection off does not stop an active scan/action — Medium

- **Location:** `agent/sentinel/watcher.py:49-52,73-101,266-270`; `agent/sentinel/tray.py:128-140`
- **Reproduction:** Block a fake scanner mid-call, disable real-time protection, then release it. The worker can still call `act_on()` and quarantine after the UI says protection is off.
- **Proof test:** `test_stop_prevents_post_stop_action`
- **Direction:** Join the queue worker, pass a cancellation generation into `_scan_one`, and suppress action if the protection instance was stopped before the decision.

### RT-019 — Native host accepts a missing caller origin — Low

- **Location:** `agent/sentinel/nativehost.py:216-223`; `agent/sentinel/__main__.py:221-226`
- **Reproduction:** Invoke native-host mode without a `chrome-extension://…` argument and send a harmless `hello` frame; the origin check permits it.
- **Proof test:** `test_native_host_requires_exact_origin_argument`
- **Direction:** Require exactly the configured origin in browser-host mode. Keep a separate explicit diagnostic mode if manual invocation is needed. Chrome documents the caller origin as the first native-host argument. [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)

### RT-020 — Content-message numeric/string validation is incomplete — Low

- **Location:** `extension/src/background.js:271-294,328-340`
- **Reproduction:** Send `page_signals` with `score: NaN` or very large `id`/`detail` strings from a synthetic content-script sender. `typeof NaN === "number"` passes; the aggregate becomes `NaN`.
- **Proof test:** `page_signals rejects non-finite scores and oversized fields`
- **Direction:** Require `Number.isFinite`, integer scores in an explicit range, allowlisted signal IDs, and length limits before any reduction, storage, UI, or native forwarding. Chrome explicitly treats content-script messages as attacker-crafted. [Chrome messaging security](https://developer.chrome.com/docs/extensions/develop/concepts/messaging#security-considerations)

### RT-021 — Allowlist synchronization silently truncates after 5,000 hosts — Medium

- **Location:** `agent/sentinel/nativehost.py:124-132`; `extension/src/background.js:106-117`; `extension/src/rules.js:45-57`
- **Reproduction:** Add 5,001 allowed hosts and make the last one overlap the blocklist. Agent navigation lookup says allowed, but the host is omitted from extension state/DNR exemptions and may be blocked before lookup.
- **Proof test:** `test_allowlist_paging_or_explicit_overflow`
- **Direction:** Page allowlists, reject unsupported growth explicitly, or use a compact rule strategy. Show “5,000 of 5,001 synchronized” rather than silently splitting authority.

### RT-022 — “Proceed anyway” creates an indefinite broad exception — Medium

- **Location:** `extension/src/background.js:301-327,364-385`; `agent/sentinel/urlintel.py:94-114`
- **Reproduction:** Proceed once from a harmless test-blocked host, close the tab, and revisit an explicitly blocklisted URL on the same host. The host remains allowed and exact URL intelligence is bypassed.
- **Proof test:** `proceed_is_one_navigation_unless_always_trust_is_selected`
- **Direction:** Default to a tab/navigation-scoped bypass. Make persistent “Always trust this site” a separate checkbox/action with the exact hostname and protections being disabled shown clearly.

### RT-023 — Failed download handoffs are silent and counted as scans — Medium

- **Location:** `extension/src/background.js:243-263`; `extension/src/popup.js:16-18`; `extension/src/popup.html:33-36`
- **Reproduction:** Make `native.request("scan_download")` reject. `downloads` is incremented before the request, the exception is discarded, and the popup labels the value “tệp đã quét.”
- **Proof test:** `completed_download_failure_is_pending_not_scanned`
- **Direction:** Increment only on a successful terminal response; persist pending/error state, retry with a cap, notify when a file could not be checked, and deduplicate with watcher scans.

### RT-024 — Traversal omissions are not represented in coverage — Medium

- **Location:** `agent/sentinel/scanjob.py:48-70,129-149`; `agent/sentinel/gate_ui.py:204-217`
- **Reproduction:** Scan a missing root plus a harmless junction to another temporary directory. The root/junction contributes no file and no structured skipped count. Long-path and directory-access failures are collapsed into free-form error text; locked enumerated files receive only a summary count.
- **Proof test:** `test_scanjob_accounts_for_missing_roots_reparse_points_locked_and_long_paths`
- **Direction:** Produce typed enumeration outcomes: `missing_root`, `reparse_skipped`, `access_denied`, `path_too_long`, `vanished`, `locked`. Report them in coverage totals. Continue to skip junctions by policy; do not silently count the requested scope as complete.

### RT-025 — Popup says “No issue detected” without a reputation verdict — Medium

- **Location:** `extension/src/popup.js:20-27,39-57`; `extension/src/background.js:186-198,344-353`
- **Reproduction:** Open a structurally ordinary URL while the agent is offline or while tab state remains pending. The popup shows agent disconnected but page state “Không phát hiện vấn đề.”
- **Proof test:** `popup_shows_not_checked_when_reputation_missing_or_pending`
- **Direction:** Use “Chưa kiểm tra danh tiếng” or “Chỉ kiểm tra cấu trúc URL”; reserve “Không phát hiện” for completed enabled checks.

### RT-026 — Real-time can report “on” with no watched directories — Medium

- **Location:** `agent/sentinel/watcher.py:124-137,252-270`; `agent/sentinel/tray.py:290-306`
- **Reproduction:** Configure only nonexistent directories. `FileWatcher.dirs` is empty, but `RealtimeProtection.running` becomes true and the header says protection is on.
- **Proof test:** `test_realtime_zero_directories_is_degraded`
- **Direction:** Separate component health: filesystem watcher, persistence watcher, and download bridge. Overall state should be “Cần chú ý” when any required component has zero coverage.

### RT-027 — Only one Run-key registry view is monitored — Medium

- **Location:** `agent/sentinel/watcher.py:140-166`
- **Reproduction:** With an injected registry adapter, place harmless entries separately in the 32- and 64-bit views; the implementation opens each key without `KEY_WOW64_32KEY`/`KEY_WOW64_64KEY`.
- **Proof test:** `test_run_monitor_reads_both_registry_views`
- **Direction:** Enumerate both views explicitly and deduplicate canonical `(hive, view, key, value-name)` records. This is already required by locked smart-scan scope.

# Part 4 — Feature plan

## A. Meaning of Scan versus Deep Scan

| Property | Scan — primary | Deep Scan — secondary, confirmed |
|---|---|---|
| Scope | Locked smart scope: watched folders, user/All Users Startup, both Run/RunOnce views, readable scheduled-task executable actions, and running process images. | Smart scope plus all readable local fixed volumes. Exclude UNC and removable media unless explicitly selected. |
| Layers | Same ordered Contract v1 pipeline for every file. | Same evidence policy; “deep” must never lower detection thresholds or make weak heuristics conclusive. |
| Cache | Reuse only complete, cacheable Contract v1 results under current engine identities. | Bypass incomplete/old clean cache; complete current-generation results may be reused only if the UI says so. |
| Core/YARA | Current 64 MiB full-content limit; front 64 MiB plus tail 8 MiB otherwise, clearly partial. | Target a file-backed/streaming implementation under the locked 192–256 MiB in-flight budget. Until available, do not call >64 MiB YARA coverage complete. |
| Archives | Current depth 3, 2,000 members, 256 MiB expanded total. | Proposed depth 6, 10,000 members, 1 GiB expanded total, processed one member at a time. Encrypted/limit-exceeded content becomes partial/unknown, not clean. |
| ClamAV | Current 400 MiB outer-stream boundary and its internal limits. | Same safe outer limit unless the ClamAV integration is redesigned; Deep must expose the boundary rather than imply unlimited scanning. |
| Time | Target approximately 15 minutes; stop only at a documented budget and offer “Continue.” | Default two-hour budget, resumable checkpoint, “Continue until complete,” and per-engine timeouts. |
| Result | `Complete`, `Partial`, `Unreadable`, `Skipped by policy`, `Engine unavailable`; counts always visible. | Same statuses, plus explicit volume/root completion. A deep scan that times out is “Stopped—72% enumerated,” never “Clean.” |

The main button should remain **Quét ngay** and run smart scope. **Quét sâu…** belongs in a secondary menu with estimated scope and confirmation.

## B. Real-time protection without a driver/admin rights

Achievable:

- Recursive monitoring of configured user-readable directories.
- Post-write/post-rename scans with bounded retries and stable file-identity checks.
- Run/RunOnce and Startup monitoring.
- Extension-triggered completed-download scans.
- Recovery scans after queue overflow, shutdown, or downtime.
- Notify-only correlation such as “new startup entry plus newly written executable.”

Must be stated plainly:

> Sentinel detects files after Windows reports that they were created or changed. It cannot guarantee blocking before a file opens or runs.

It also cannot reliably provide process attribution, memory scanning, exploit prevention, kernel/driver monitoring, protected-folder interception, or trusted ransomware rollback.

## C. Helium extension priorities

1. Fix RT-020 through RT-025 before adding signals.
2. Make bypass one-time by default; expose persistent trust separately.
3. Give each tab an explicit state: `checking`, `checked`, `limited`, `agent offline`, `allowed`.
4. Persist and retry failed download scans; show last successful scan and pending count.
5. Add blocklist/allowlist coverage counters and stale-data age.
6. Add search-result reputation only after the URL-verdict contract and privacy model are defined.
7. Keep page heuristics advisory. The README’s own measurement shows they currently add little detection value.
8. Do not market the extension as equivalent to Safe Browsing/SmartScreen without cloud/file prevalence or novel-threat telemetry.

## D. Additional features ranked

| Rank | Feature | User-mode feasibility / effort / FP risk | Plan position | Harmless proof |
|---:|---|---|---|---|
| 1 | Scan history with coverage and rerun/export | Fully feasible; **M**; low FP | Immediately after Contract v1 | Mixed clean/partial/unreadable fake results survive restart and export without changing labels. |
| 2 | Scheduled smart scans | Task Scheduler or in-agent scheduler; **M**; low FP | After smart scan | Injected clock triggers once, respects battery/idle policy, and records a missed run without duplicate scans. |
| 3 | Protection health/self-test | Fully feasible; **M**; no detection FP | After C3 fixes | Fake stale feeds, stopped clamd, empty watch set, disconnected extension, and healthy state produce distinct statuses. |
| 4 | Scoped exclusions UI | Feasible; **M**; medium protection risk | After quarantine hardening | Path+hash and expiring folder exceptions work only in scope; malicious evidence outside scope remains actionable. |
| 5 | Explorer “Scan with Sentinel” | Per-user shell registration; **S**; low FP | After stable scan contract | Invoke handler with harmless file, directory, spaces, and Unicode; argv remains an array with `shell=False`. |
| 6 | USB/removable-drive scan on insertion | Feasible through user-mode device/volume notifications; **M**; low FP | After smart scan | Synthetic volume-arrival provider queues a temporary directory once and handles removal during scan as partial. |
| 7 | Startup-item review | Reuse smart-scan registry/task/Startup enumerators; **M**; medium UX FP | Alongside smart scan | Known harmless startup entries display publisher/path/source; “unknown” never means malicious. |
| 8 | Signer and optional download/hash reputation | Authenticode feasible locally; network reputation needs privacy/licensing; **M/L**; medium FP/privacy risk | After quarantine hardening | Fake trusted/revoked/unknown/offline responses; reputation must not override conclusive local malware evidence. |

The current HTML/JSON report should become an export of scan history rather than a separate top-level feature.

# Part 5 — UI and animation review

## What currently looks generic or “AI-made”

The screenshot reads like a polished developer panel, not a finished home-security product:

- Four colored dots, four technical descriptions, five scan buttons, a thin progress bar, and a nine-column table all compete at the same visual level.
- “Các lớp kiểm tra (tệp phải qua tất cả)” is both technical and untrue in edge cases.
- “Cổng quét” sounds infrastructural. Use **Quét** or **Trình quét**.
- The wide empty results grid dominates the window even when there is nothing actionable.
- Full paths, engine columns, score, conclusion, action, and reason repeat the same information.
- Pure near-black `#0b0b0c` plus thin grey borders produces a generic terminal/dashboard look. There is little tonal hierarchy between background, cards, and tables.
- The 9-point type scale is nearly uniform; title, section heading, body, metadata, and table labels differ mostly by boldness.
- Uppercase `PHÁT HIỆN` and raw numeric risk scores make weak and conclusive evidence look more precise than it is.
- The top-right real-time status duplicates information elsewhere and can claim protection with zero watched folders.

Windows Security uses a small number of protection areas with green/yellow/red status and recommended actions; it does not expose every internal engine on the landing page. [Windows Security overview](https://support.microsoft.com/en-gb/windows/security/windows-security/windows-security-app-overview) Bitdefender similarly promotes a few quick actions and moves scan configuration deeper. [Bitdefender Quick Actions](https://www.bitdefender.com/consumer/support/answer/13354/)

## Recommended main screen

Use a two-level information hierarchy.

**Header**

- Logo and “Sentinel Guard”
- Overall state: **Đang bảo vệ**, **Cần chú ý**, or **Bảo vệ đang tắt**
- Compact secondary text: `Cập nhật 12 phút trước · 0 mục cần xử lý`

**Three feature cards in one row**

1. **Bảo vệ thời gian thực**
   - `Bật · 5 thư mục đang theo dõi`
   - Secondary: `Phát hiện sau khi tệp được ghi`
   - Actions: **Quản lý**, toggle

2. **Bảo vệ web**
   - `Helium đã kết nối`
   - Secondary: `398.214 tên miền · đồng bộ 12 phút trước`
   - Error form: `Agent chưa kết nối — bảo vệ danh sách cục bộ vẫn hoạt động`
   - Action: **Mở tiện ích**

3. **Quét**
   - Primary: **Quét ngay**
   - Secondary split/menu: **Quét sâu…**, **Chọn tệp hoặc thư mục**
   - Last result: `Lần cuối: 1.204 tệp · 2 mục cần xem`

**Below the cards**

- During a scan: live pipeline, current file shortened to basename, counts, elapsed time, coverage, and Stop.
- Otherwise: **Hoạt động gần đây**, at most 8 rows.
- Put per-engine results behind **Chi tiết kỹ thuật** or the row-detail dialog.

Tabs should become: **Tổng quan**, **Quét**, **Lịch sử**, **Cách ly**, **Cài đặt**. Web events and trusted sites belong under Web protection or Settings, not equal-weight top-level tabs.

## Copy and state changes

Remove or shorten:

- `Các lớp kiểm tra (tệp phải qua tất cả)` → `Các lớp bảo vệ`
- `không phải phần mềm diệt virus đang chạy (bỏ qua)` → `Không hoạt động`
- `engine mã nguồn mở, mở 7z/RAR/CAB/ISO/PDF/Office` → move to details
- `bật · chữ ký hash: 0` → `Sẵn sàng`
- `chưa có chữ ký nào` → `Chưa cài bộ luật`
- `PHÁT HIỆN` → `Có tín hiệu` for weak evidence; `Đã xác nhận` for conclusive evidence

Use separate counts:

- `1.204 tệp đã kiểm tra`
- `1 mối đe dọa`
- `1 mục nghi ngờ`
- `1 tệp đã cách ly`
- `3 tệp chưa đọc được`
- `27 tệp chỉ được kiểm tra một phần`

Do not combine suspicious and malicious as `2 phát hiện`.

Empty state:

> **Chưa có mục cần xử lý**  
> Kết quả nghi ngờ và mối đe dọa sẽ xuất hiện ở đây.

Engine error:

> **ClamAV chưa sẵn sàng**  
> Quét vẫn tiếp tục với 2 trong 4 lớp. Kết quả sẽ được đánh dấu là kiểm tra một phần.  
> **Khởi động lại**

Use **Chưa kiểm tra**, not **Không phát hiện vấn đề**, whenever agent reputation or an engine result is missing.

For typography, use Segoe UI/Segoe UI Variable, regular body and semibold headings, sentence case, approximately 10 pt body, 9 pt metadata, 13–15 pt section/title. Microsoft’s Windows guidance recommends one type family, regular/semibold hierarchy, and avoids undersized text. [Windows typography](https://learn.microsoft.com/en-us/windows/apps/design/signature-experiences/typography)

## Motion

| Current motion | Decision | Proposed behavior |
|---|---|---|
| Status-dot fade | Keep, shorten | 167 ms ease-out, only when state changes. Current 200 ms linear stepping is acceptable but mechanically uniform. |
| ClamAV breathing dot | Keep with limits | 1.6 s ease-in-out, opacity approximately 60–100%; stop after the startup deadline and transition to a static warning. |
| Sliding 2 px activity bar | Change | Use determinate progress when enumeration is known. For indeterminate work, a 25% segment with a 1.4 s ease-in-out cycle; pause when no work is active. |
| Logo sweep | Drop | It duplicates the progress bar and adds decoration without communicating a different state. |
| New-row flash | Keep only for actionable rows | One 333 ms fade from a 12% severity tint to the normal surface. Do not flash clean rows or every pipeline event. |

Windows motion guidance favors fast, purpose-specific animation with 167/250/333 ms timings and easing; the current logo sweep and continuously linear bar feel more like generated dashboard ornament. [Fluent motion guidance](https://learn.microsoft.com/en-us/windows/apps/design/signature-experiences/motion)

Respect the Windows “show animations” accessibility setting; disabling it should make every state transition immediate.

## Logo

At 16 px, the current mark is not reliably legible:

- On a dark taskbar, the black center and default dark-grey outline nearly disappear.
- On a light taskbar, the silhouette is clearer, but the internal eased gradient becomes indistinct.
- The status ring is effectively one downsampled pixel. The supposed green normal state is actually neutral grey (`tray.py:30`), so health is not apparent.

Recommended change:

- Create pixel-hinted 16, 20, 24, and 32 px variants rather than relying on a 64 px gradient being downscaled.
- Replace the gradient at ≤24 px with a solid mid-grey interior.
- Use a two-tone keyline: one dark and one light edge so the square survives both taskbar themes.
- Add a distinct 4–5 px status corner/underline: green healthy, amber degraded/offline, red action required.
- Keep the current more detailed gradient only at 32 px and above.
- Validate all variants on light/dark taskbars at 100%, 125%, 150%, and 200% scaling.

# Sources

- [Microsoft Defender scan modes](https://learn.microsoft.com/en-us/defender-endpoint/schedule-antivirus-scans)
- [Microsoft Defender always-on protection](https://learn.microsoft.com/en-us/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus)
- [Microsoft Defender scan triggers](https://learn.microsoft.com/en-us/defender-endpoint/configure-extension-file-exclusions-microsoft-defender-antivirus)
- [Microsoft filesystem minifilters](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers)
- [Bitdefender scan guide](https://www.bitdefender.com/consumer/support/answer/1477/)
- [Bitdefender custom scans](https://www.bitdefender.com/consumer/support/answer/2056/)
- [Bitdefender Shield](https://www.bitdefender.com/consumer/support/answer/13450/)
- [Bitdefender Advanced Threat Defense](https://www.bitdefender.com/consumer/support/answer/2024/)
- [Malwarebytes scan types](https://help.malwarebytes.com/hc/en-us/articles/31589479207579-Scan-types-in-Malwarebytes-for-Windows-and-Mac)
- [Malwarebytes real-time protection](https://help.malwarebytes.com/hc/en-us/articles/31589448817563-Turn-on-Real-Time-Protection-in-Malwarebytes-for-Windows-and-Mac)
- [Malwarebytes Browser Guard](https://www.malwarebytes.com/solutions/safe-browser)
- [Browser Guard block pages](https://help.malwarebytes.com/hc/en-us/articles/31589238609563-Types-of-block-pages-caused-by-Browser-Guard)
- [Bitdefender TrafficLight](https://www.bitdefender.com/en-us/consumer/trafficlight)
- [Google Safe Browsing v5](https://developers.google.com/safe-browsing/reference)
- [Chrome Enhanced Protection](https://support.google.com/chrome/answer/13844634?hl=en)
- [Microsoft SmartScreen for Edge](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-security-smartscreen)
- [SmartScreen application reputation](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation)
- [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
- [Chrome messaging security](https://developer.chrome.com/docs/extensions/develop/concepts/messaging#security-considerations)
- [Windows Security UI overview](https://support.microsoft.com/en-gb/windows/security/windows-security/windows-security-app-overview)
- [Windows typography](https://learn.microsoft.com/en-us/windows/apps/design/signature-experiences/typography)
- [Windows motion](https://learn.microsoft.com/en-us/windows/apps/design/signature-experiences/motion)