# RED18: Logs, events, and privacy

The tests below are in `tests/codex/test_red18_logs.py`. They were reviewed against source, not run in this sandbox.

## High: SYSTEM-owned file events reach any medium-integrity caller

- **Attacker:** An ordinary local process with access to the service pipe.
- **Steps:** Wait for the service to record an observed detection on a SYSTEM-owned file, then request `events` as a different medium-integrity user. The in-process test inserts the same event shape and calls `ServiceCore.handle`.
- **Effect:** The caller receives the path and threat details for a file it cannot read. Failed owner lookup also yields an empty owner, which takes the same permissive branch.
- **Lines:** `agent/sentinel/service/backend.py:431-436` obtains the owner; `agent/sentinel/service/backend.py:535-545` records it through `act_on`; `agent/sentinel/service/backend.py:389-408` serves events; `agent/sentinel/service/backend.py:671-674` returns visible for every owner SID outside the two user SID prefixes, including `S-1-5-18` and empty owner. `agent/sentinel/service/core.py:264-265` and `agent/sentinel/service/protocol.py:188` make the stream available to ordinary users.
- **Fix:** Treat SYSTEM, administrators, unknown ownership, and malformed ownership as private for path-bearing events. Keep explicitly classified machine-wide status events visible; do not infer public visibility from an unfamiliar SID prefix.
- **Proof:** Proven by `test_system_owned_event_is_not_disclosed_to_medium_caller`; the event ingestion shape is matched, while the live Windows pipe and ACL are inferred from the cited code.

## Medium: A Run value name can forge a service log line

- **Attacker:** Ordinary user controlling an HKCU Run value name; the restore fails while the privileged service handles a repair undo.
- **Steps:** Put a newline and bidi override in the value name, arrange a failed restore, then inspect the service log. The test supplies a failing registry object without touching the real registry.
- **Effect:** One warning becomes multiple displayed log lines, including an attacker-written fake critical message. This can mislead an administrator reviewing an incident.
- **Lines:** `agent/sentinel/service/repair.py:324-332` logs the raw value name after `SetValueEx` fails; `agent/sentinel/service/entry.py:63-67` uses a line-oriented formatter and file handler. The same raw pattern exists at `agent/sentinel/service/repair.py:299-312` for a failed removal.
- **Fix:** Escape control and bidi characters in untrusted log fields before formatting, preferably in a shared log-safe formatter for all service log calls. Preserve a readable representation of the actual value name.
- **Proof:** Proven in process by `test_failed_restore_escapes_run_value_before_logging`; reachability from a real HKCU value and actual log ACL are inferred.

## Medium: Bidi file names enter threat events without display escaping

- **Attacker:** A file with a valid Windows name containing a Unicode direction override.
- **Steps:** Create a file named with U+202E containing the harmless test marker, scan it with the test-only rule, and record the malicious verdict with quarantine disabled. Read the event detail presented to the user.
- **Effect:** The path can render with a deceptive apparent suffix or reversed segment in event views, misleading the user about which file was detected.
- **Lines:** `agent/sentinel/protection.py:88-112` writes `v.name` directly into event detail; `agent/sentinel/db.py:585-589` stores it unchanged; `agent/sentinel/service/backend.py:399-400` returns it to clients. `agent/sentinel/service/repair.py:40-56` already has a display-safe helper, but this path does not use it.
- **Fix:** Escape bidi and control characters in event display fields at the event boundary, retaining an unambiguous path in structured data where needed.
- **Proof:** Proven in process by `test_bidi_filename_is_escaped_in_threat_event`; visual reversal in a particular font is inferred.

## Medium: Overview can show protection on after the service turns it off

- **Attacker:** A crash, service stop, or approved protection-off action while the user's tray watcher continues running.
- **Steps:** Make local watcher, feeds, browser status, and ClamAV healthy, but supply `{"realtime": false}` from the service status poll.
- **Effect:** The main state still says `Đang bảo vệ`, hiding the stopped service from the user.
- **Lines:** `agent/sentinel/overview_ui.py:33-54` uses only `app.realtime.running` and `worker_failure` to choose the state; `agent/sentinel/overview_ui.py:185-212` fetches service status and passes it in; `agent/sentinel/service/backend.py:346-362` reports the actual service `realtime` state.
- **Fix:** When the service status is available, include its real-time state in the top-level protection decision and show an off/attention state when it is false.
- **Proof:** Proven in process by `test_overview_respects_service_realtime_off`.

## Other probes

- **Medium write/replace of service log:** No finding. `agent/sentinel/service/installer.py:20-22,793-806` requires SYSTEM/administrator-only ACLs on the state tree, including the journal, and `agent/sentinel/service/integrity.py:91-106` checks them at startup.
- **Log growth:** No finding. `agent/sentinel/service/entry.py:63-67` configures a 5 MiB rotating log with three backups. Event rows are pruned by `agent/sentinel/db.py:602-608` from the service maintenance loop at `agent/sentinel/service/backend.py:255-263`. I did not establish a bounded-time attacker path that defeats those controls.
- **ETW diagnostics:** `agent/sentinel/service/etw.py:946-960` hex-logs up to 160 bytes of raw process event payload on check failure; those bytes may include command lines per `agent/sentinel/service/etw.py:104-125`. The installed service log is protected by the ACL above, so this round does not claim a medium-integrity read of those bytes.
