# RED4: native host and extension messaging

No tests were run in this sandbox. The three tests use `tmp_path`, the autouse temporary `SENTINEL_HOME`, and fake service replies; Claude should run them and review the fixes. No live service, network, or malware is involved.

## High: service outage grants browser trust without approval

**Test:** `test_offline_service_does_not_grant_local_host_trust` (proven by the in-process test).

**Attacker and steps:** An ordinary user process or a page that persuades the user to choose “always trust” during a brief service outage asks the native host to allow a blocked host. The test models a configured but unavailable service. `Host.on_allow_host` checks `lease.available()` and writes to the user database when it is false. The extension also installs an allow rule immediately when the native request succeeds. With a stopped or restarting service, the host silently changes the local trust list without an administrator confirming it. Even when the native host itself is unreachable, `trust()` queues the host and installs an allow rule before the next sync.

**Effect:** Browser block and warning rules are bypassed until a later authoritative sync removes the trust entry. A service outage can therefore turn an administrator-gated choice into a user-level choice.

**Lines:** `agent/sentinel/nativehost.py:191-205`; `extension/src/background.js:146-169`, `170-203`, `474-503`; `extension/src/rules.js:72-85`. The service-backed path uses approval at `agent/sentinel/service/bridge.py:152-167`.

**Fix:** Distinguish a genuinely uninstalled standalone agent from a configured service that is temporarily unavailable. In the latter state, reject or queue the request without adding browser or local allow rules. Apply trust only after the service confirms the approved plan. The test asserts that an unavailable lease cannot alter the local allowlist.

## High: a stale service result reports changed bytes clean

**Test:** `test_changed_download_is_not_reported_clean_from_stale_service_verdict` (proven by the in-process test; exploit timing inferred).

**Attacker and steps:** A file owner lets the service scan harmless bytes, then replaces the file before the native host receives the service reply. The fake lease in the test makes that timing deterministic and returns the original SHA-256. The native host returns the clean verdict without checking whether the path still names those bytes.

**Effect:** The extension removes the download from pending and counts it as scanned, although the current file was never measured. A later watcher scan may occur, but the immediate user-facing answer is false.

**Lines:** `agent/sentinel/nativehost.py:154-168`; `extension/src/background.js:318-324`, `338-365`; `agent/sentinel/service/backend.py:501-515`, `525-551` (service verdict contains the measured SHA-256).

**Fix:** Return measured file identity to the browser and compare it with the completed download before marking it scanned, or hold a stable file handle through scan and final disposition. A changed or missing file must remain pending/unknown and be rescanned; never report the old clean verdict as the current file's result.

## Medium: blocked download source loses its warning after a cancel race

**Test:** `test_completed_blocked_url_download_keeps_source_warning` (proven by the in-process native-host test; browser timing inferred).

**Attacker and steps:** A blocked URL serves a small harmless file that completes before the asynchronous `check_url` response causes `chrome.downloads.cancel`. The completed-file path scans its bytes. The service returns a clean file verdict and a malicious `url_reputation`; the native host passes both through. `scanDownload` only reacts to `verdict.label`, so it treats this as a successful clean scan and gives no source warning.

**Effect:** The file remains on disk while the completed-file path counts a clean scan. The earlier callback may already have notified the user that the download was blocked even though cancellation lost the race. The comment promising quarantine after that race does not match the service-backed path. This finding does not require treating a caller-supplied URL as authority to quarantine an arbitrary path.

**Lines:** `extension/src/background.js:297-324`, `338-365`; `agent/sentinel/nativehost.py:161-168`; `agent/sentinel/service/backend.py:507-510`, `525-554`; compare local-only origin escalation in `agent/sentinel/nativehost.py:169-173` and `agent/sentinel/protection.py:45-52`.

**Fix:** Carry an explicit blocked-source status in the native response and show it for completed downloads even when file bytes scan clean. If removing a completed download, tie the action to the browser's download ID and verified provenance, not the untrusted URL field alone. The test asserts that the response exposes `blocked_source`.

## Other probes

The extension's privileged message types are restricted to extension pages, and `proceed` binds the warning URL to the tab (`extension/src/background.js:373-428`); no direct page-to-native scan or trust request was found. Service path checks test caller readability (`agent/sentinel/service/core.py:169-175`), so no cross-user file read was established. Host names over 253 characters are rejected (`agent/sentinel/nativehost.py:191-196`); the service normalizes Unicode hosts to IDNA before composing approval text (`agent/sentinel/service/backend.py:683-690`). No long-host or IDN approval spoof was established. Repeated page navigation alone does not reach the approval call; it requires an extension-page action (`extension/src/background.js:373-428`), so no page-driven prompt flood was established. Input frames over 1 MiB are drained in chunks (`agent/sentinel/nativehost.py:226-240`), and host responses over 1 MiB are replaced with an error (`agent/sentinel/nativehost.py:269-279`); existing tests already cover the input boundary. Slow requests use two worker threads (`agent/sentinel/nativehost.py:294-305`), but no page-reachable path to an unbounded native request flood was established.
