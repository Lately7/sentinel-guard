# RED27 — browser extension, second pass

No pytest command was run in this sandbox. Each test uses `tmp_path` and the autouse temporary `SENTINEL_HOME`. The first two exercise the native host and database in process; the third checks the extension source contract in process. Browser outcomes are identified as inferred below.

## High — a completed download is lost if the browser dies during its scan

**Test:** `test_completed_download_is_journaled_before_native_scan` (source contract proven; browser loss inferred).

**Attacker model and steps:** A crash or power loss follows a `downloads.onChanged` completion event while `scanDownload` awaits the native request. The extension records a pending download only in the request's catch path. A stopped browser cannot run that catch; Chromium does not replay the already delivered completion event on restart.

**Effect:** The file is neither counted as checked nor retained for retry. The popup's pending count omits it, and the retry alarm has no entry to visit. Other filesystem observers may independently find it, but this download scan has been lost.

**Lines:** `extension/src/background.js:318-325,327-365,541-546`; `extension/src/pending.js:9-24`; `extension/src/popup.js:21-25`.

**Fix:** Save the completed download ID, path and URL to durable pending storage before awaiting `scan_download`. Remove the entry only after a definitive result. On startup, schedule a retry for saved entries, including one left by an interrupted request.

## Medium — service `unknown` is replaced by a local `clean` download verdict

**Test:** `test_unknown_service_download_cannot_be_reported_clean` (proven in process).

**Attacker model and steps:** A downloaded file reaches the service while a required scanner stage fails. The service returns a completed job with verdict `unknown`. The native host treats that label as a reason to fall through to its own scanner, whose available stages can report `clean`. The test makes the two responses deterministic with an in-process fake lease and scanner.

**Effect:** The extension removes the download from pending and increments the checked count, while the service explicitly could not finish the required check.

**Lines:** `agent/sentinel/nativehost.py:154-173`; `agent/sentinel/engine/scanner.py:122-175` (required stage selection); `extension/src/background.js:338-365`.

**Fix:** Preserve a service `unknown` result as `unknown` (or return an error that keeps the download pending). A local supplementary scan may add findings, but a local `clean` result must not erase the service's incomplete status.

## Medium — removing trust does not restore a previously omitted block rule

**Test:** `test_allow_removal_changes_effective_blocklist_version` (native-host version mismatch proven in process; browser effect inferred).

**Attacker model and steps:** In standalone mode, a listed host is already trusted when the extension performs a full sync. `blocked_hosts()` excludes trusted hosts, so the dynamic block rules omit it. The user removes that trust in the dashboard. The native host's effective blocklist now contains the host, but `hello.blocklist_version` remains the same. The extension notices the changed allowlist version, removes the allow rule, and takes its unchanged-blocklist branch without fetching the newly effective blocklist.

**Effect:** Navigation to the listed malicious host is no longer protected by a network rule until a forced or feed-driven full sync. A per-navigation native lookup may still warn when available.

**Lines:** `agent/sentinel/db.py:467-487,530-544`; `agent/sentinel/nativehost.py:95-102,110-131`; `extension/src/background.js:170-203,221-226`.

**Fix:** Make the version in `hello` cover the effective blocklist, including local trust changes, or force a full blocklist fetch whenever the allowlist changes. Keep the version used for paging aligned with the advertised version.

## Other probes

The `proceed` message binds its URL to the tab and rechecks the threat (`extension/src/background.js:393-425`); this pass did not establish a new page-to-native privilege path. The popup's `trust_site` request reaches the native host's approval path (`extension/src/popup.js:69-73`, `background.js:474-503`, `agent/sentinel/nativehost.py:191-205`); the already reported offline trust issue in RED4 remains the approval concern. Completed downloads are resolved by ID at `background.js:318-325`, and retries retain a pathname at `pending.js:9-24`; RED12 already covers pathname replacement, so it is not repeated here. RED4 and RED12 also cover completed blocked-source handling, forged warning display, and stale page signals.
