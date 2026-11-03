# RED23 — Tray and overview UI

These are in-process regression tests. They use `tmp_path`, the test suite's temporary `SENTINEL_HOME`, and fake UI/service objects. Pytest was not run in this sandbox.

## High — Service protection off, hero still says protected

- **Attacker model:** A service protection failure or independent service disable while the user's separate tray watcher remains running.
- **Steps:** Keep local `realtime.running=True`; return service status `{"realtime": false, "worker_failure": ""}`; keep feeds and extension fresh. `protection_state` checks only local realtime and `worker_failure`, then returns `State("ok", "Đang bảo vệ", ...)`.
- **Effect:** The main protection indicator claims protection even though the LocalSystem service reports its realtime barrier is off. The user is not told that service-owned scanning/actions stopped.
- **Lines:** `agent/sentinel/overview_ui.py:37-54`; the service's authoritative `realtime` field is built at `agent/sentinel/service/backend.py:346-362`.
- **Proposed fix:** Incorporate an available service status's `realtime` flag into the hero state. Show attention or off when the service says false; distinguish a never-installed service from a previously responding service that disappears.
- **Proof:** Proven by `test_service_realtime_off_does_not_show_protected`.

## High — An unreadable scan is labeled “Sạch”

- **Attacker model:** A downloaded file that the scan cannot open (for example, sharing or access denial).
- **Steps:** A scan raises while reading the target. `ScanJob` records an error and scans no bytes, but emits a `scan` event at `info` level because its level depends only on detections. The overview interprets the latest `info` scan event as “Sạch”.
- **Effect:** The user sees a clean scan result for a file that was never checked.
- **Lines:** `agent/sentinel/scanjob.py:161-182`; `agent/sentinel/overview_ui.py:231-243`. The detailed gate UI does mention unreadable/error counts at `agent/sentinel/gate_ui.py:305-313`, but the overview does not.
- **Proposed fix:** Record incomplete scans as warning, including errors, unreadable, unknown and uncovered scope; have the overview read scan completion metadata rather than equating `info` with clean.
- **Proof:** Proven by `test_unreadable_scan_does_not_show_clean` with a harmless temporary file and a scanner that raises `OSError`.

## High — Notification failure consumes later threat alerts

- **Attacker model:** A medium-integrity process creates a burst of warning events in the per-user database under LocalAppData, followed by a threat; the Windows notification backend rejects one notification. Web warning reports are another source of events.
- **Steps:** `take_unnotified` selects every warning/threat and marks the whole batch notified before the tray sends any notification. The sixth `icon.notify` raises. `_notifier` catches the exception around the whole loop, so every remaining event, including the threat, stays marked notified and is never retried.
- **Effect:** A real threat alert is silently lost and the red tray icon is not set for that threat.
- **Lines:** `agent/sentinel/db.py:610-616`; `agent/sentinel/tray.py:208-218`; web report insertion `agent/sentinel/nativehost.py:175-188`; per-user state path `agent/sentinel/config.py:25-35`.
- **Proposed fix:** Deliver bounded batches with threat priority, and acknowledge each event only after its notification succeeds. Keep failed events pending with bounded retry/backoff; update the red icon independently of toast success.
- **Proof:** Proven by `test_notification_failure_keeps_later_threat_pending` for an event burst and a failed toast. The frequency of web reports from an actual hostile page is not established by this test.

## Medium — Crafted file names can reorder notification text

- **Attacker model:** A downloaded file with a Unicode bidi control in its name.
- **Steps:** The service includes a shown path in event detail. The tray passes the detail directly to the Windows notification API; a right-to-left override can change the apparent order of an extension or surrounding alert text.
- **Effect:** The notification can mislead the user about which file triggered the warning.
- **Lines:** Service event detail path at `agent/sentinel/service/backend.py:478` and `:577`; unsanitized notification at `agent/sentinel/tray.py:199-205`. The local notification path also passes raw event text at `:212-216`, and history/recent labels use raw text at `agent/sentinel/tray.py:365-394` and `agent/sentinel/overview_ui.py:251-266`.
- **Proposed fix:** At every UI boundary, render bidi and nonprinting controls visibly or remove them while preserving the original value in stored evidence. Apply the same conversion to toast, tables, detail labels and scan progress.
- **Proof:** Proven for the service toast by `test_service_notification_neutralizes_control_text`; other listed UI surfaces are inferred from their direct rendering calls.

## Medium — A slow service lookup blocks the dashboard

- **Attacker model:** A stalled LocalSystem service or slow named-pipe response during a refresh.
- **Steps:** The Tk pump calls `refresh` on the main thread; `refresh` synchronously calls `lease.quarantine_items()`, which may connect to and read from the service. A delayed response holds the Tk thread.
- **Effect:** The dashboard stops processing input and redraws while the service responds; the path repeats on periodic refresh.
- **Lines:** `agent/sentinel/tray.py:143-153`, `:359-385`; `agent/sentinel/service/bridge.py:77-93`, `:130-132`; blocking request/response at `agent/sentinel/service/client.py:53-64`.
- **Proposed fix:** Poll quarantine data in a worker with a generation/cached snapshot, then post a short UI update. Keep refresh free of service I/O; report stale data visibly.
- **Proof:** Proven by `test_dashboard_refresh_does_not_wait_for_service` with an in-process delayed lease. A real service stall is inferred.
