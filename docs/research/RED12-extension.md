# RED12 — browser extension

No pytest command was run in this sandbox. The tests below are proposed regressions; the first exercises the native-host fallback in process, and the other three check source contracts. Runtime browser effects of the source-contract tests are inferred.

## 1. Download pathname replacement applies a hostile URL to another file — high

- **Attacker:** ordinary user process with write access to the download directory, racing a completed browser download.
- **Steps:** a download finishes; before the native request is handled, move the downloaded file aside and put a benign file at the same pathname. The extension searches by download ID, takes only `item.filename` and `item.finalUrl || item.url`, then sends `path` and `url`. Mark the URL's host as malicious in the local indicator DB. When the service is unavailable, the native-host fallback scans the replacement bytes, adds a critical origin finding, and can quarantine that replacement.
- **Effect:** the file associated with the browser download escapes this scan, while a different file can be quarantined in fallback mode. The service-backed path also scans the replacement path but explicitly treats the URL as report-only, so this particular wrong-quarantine effect is limited to fallback. A later filesystem watcher may independently catch the moved file.
- **Lines:** `extension/src/background.js:318-325,338-355`; `agent/sentinel/nativehost.py:154-173`; `agent/sentinel/protection.py:45-52,96-103`; `agent/sentinel/service/core.py:233-236`; `agent/sentinel/service/backend.py:507-520,531-552`.
- **Fix:** bind the completed download to a file identity before acting on it, and carry that identity through the native request and service scan. Refuse or retry when the path no longer names that file. Make the native-host fallback treat URL reputation as report-only, as the service does. Size alone is insufficient because a replacement can have the same length.
- **Test:** `test_download_origin_cannot_quarantine_replacement`. **Inferred until Claude runs the in-process test.** The test exercises the native-host fallback only; the service-backed path is a separate case.

## 2. A web page can suppress the in-page warning — medium

- **Attacker:** malicious page controlling its own DOM and stylesheet.
- **Steps:** create an element with ID `sentinel-guard-banner` before the content script's callback, or hide/remove the content script's host element. `banner()` returns on the matching ID. The shadow root protects contents from direct selection, but its host stays in the page DOM. The service worker answers with `warn: true` but creates no browser-owned warning for `page_signals`.
- **Effect:** the page can make the visible credential warning disappear while leaving the risk signals intact. The popup badge may still warn if the user checks it.
- **Lines:** `extension/src/content/page_guard.js:43-48,54-65,80-83`; `extension/src/background.js:429-445`.
- **Fix:** present the warning in browser-owned UI from the worker, such as a notification or a verified warning-page navigation, and keep the DOM banner supplemental. Avoid treating a page-created ID as proof that an extension banner exists.
- **Test:** `test_page_warning_has_browser_owned_surface`. **Inferred browser effect; source contract checked by the test.**

## 3. Removed page signals remain in the popup — medium

- **Attacker:** page that changes a login form after the content script reports it.
- **Steps:** show a password form that yields `page_signals`, then remove it or change it to a non-password input. `check()` returns on an empty signal list without sending it. The worker retains `page` and `total`; the popup uses that stored total for its status.
- **Effect:** the popup continues to describe the current page as suspicious after the observed condition is gone. This can also leave stale reasons after a single-page app changes state.
- **Lines:** `extension/src/content/page_guard.js:71-83,97-99`; `extension/src/background.js:429-445`; `extension/src/page_status.js:5-14`; `extension/src/popup.js:48-54`.
- **Fix:** send an empty `page_signals` update when signals disappear, then clear `page` and recompute `total` in the worker. Include a document identity so an old page cannot clear a newer navigation's state.
- **Test:** `test_empty_page_signals_clear_worker_state`. **Inferred browser effect; source contract checked by the test.**

## 4. Web-accessible warning page renders forged threat context — medium

- **Attacker:** malicious web page that opens a URL in the extension's declared web-accessible resources.
- **Steps:** open `src/blocked.html?k=m&u=https%3A%2F%2Fexample.test%2F&src=official` under the extension origin. `blocked.js` reads the kind, URL, and source from its query string and renders them without asking the worker when `u` exists. The page can display a genuine Sentinel Guard warning with attacker-chosen threat details. The `proceed` action is separately guarded in the worker; this finding concerns what the user sees.
- **Effect:** forged security warnings can mislead the user about a site or source.
- **Lines:** `extension/manifest.json:30-32`; `extension/src/blocked.js:3-18,21-35`; `extension/src/background.js:391-411`.
- **Fix:** have the warning page obtain verified threat context from the worker for every display. Reject an unassociated tab/navigation and do not render URL, kind, or source supplied only through the query string.
- **Test:** `test_blocked_page_requires_verified_context_before_render`. **Inferred browser effect; source contract checked by the test.**

## Boundaries checked without a finding

The content script uses the default isolated world (`extension/manifest.json:21-23`), and the worker checks `sender.id`, extension-page origin, message shape, tab, and frame for privileged operations (`extension/src/background.js:373-411`; `extension/src/messages.js:17-32`). The manifest has no `externally_connectable` entry and no custom extension-page CSP override (`extension/manifest.json:1-33`). Page code has no direct access to `chrome.storage.local` or `chrome.storage.session`; the observed influence is through the DOM and browser download metadata. Broad host access and the declared permissions map to navigation scoring, DNR, downloads, native messaging, notifications, alarms, tabs, and storage in the worker (`extension/manifest.json:8-23`).
