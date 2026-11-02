# R12c — osquery 5.24.0, read from source (Windows parts)

The current directory is a checkout of osquery at tag `5.24.0`. Sentinel
will not embed osquery; the goal is to learn exactly how a mature project
reads Windows state from user mode, for Sentinel's locked smart-scan scope
(PROJECT_CONTEXT.md §10) and for evidence such as signer identity.

## Questions

For each table below, find the implementation under `osquery/tables/` (and
`osquery/core/windows/` helpers), then answer: which Windows API it calls,
what privileges it needs, what it does when access is denied or data is
malformed, 32/64-bit registry handling, and its performance shape.

1. **Autostart and persistence:** `startup_items`, `registry` (Run/RunOnce,
   both views?), `scheduled_tasks` (Task Scheduler COM API?), `services`,
   `wmi_cli_event_consumers` / `wmi_event_filters` / `wmi_filter_consumer_binding`,
   `drivers`, `appcompat_shims`, `ie_extensions`, `chrome_extensions` (does it
   support Chromium forks / custom profile paths like Helium?).
2. **Processes and files:** `processes` (image path via which API; what it
   returns for protected processes), `process_open_sockets`, `file`,
   `hash`, `authenticode` (WinVerifyTrust usage, revocation, catalog-signed
   files, error codes), `ntfs_acl_permissions`, `file` zone identifier /
   Mark-of-the-Web if any.
3. **Events:** `ntfs_journal_events` / USN journal, `windows_events`,
   `powershell_events`, `process_etw_events`: what requires admin or ETW
   sessions, and what Sentinel (no admin) cannot use.
4. **Robustness patterns.** How osquery bounds work per query, avoids
   blocking on slow files, canonicalises paths, handles junctions/reparse
   points, long paths, and Unicode; its watchdog/resource limits.

## Deliverable

Sections 1–4 with tables (table → API → privilege → failure behaviour →
`path:line`), then "Implications for Gate v2 and smart scan": the exact
Windows APIs Sentinel should call from Python (ctypes/pywin32-free where
possible) for each smart-scan source and for Authenticode, with the
fallback/coverage status when access is denied.
