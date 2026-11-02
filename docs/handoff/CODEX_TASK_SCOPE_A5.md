# Codex task — smart/deep scan scope (M8, A4) and real-time observers (A5)

Claude reviews every line, runs the tests and merges. Stay on the branch this worktree is
on; do not commit.

**Sandbox note:** you cannot run pytest in this sandbox (temp folder denied). That is *not*
a reason to stop: implement everything, re-read your code against each test, and say which
test covers what. Never create temp or probe folders. Claude runs the suites.

## Read first

`docs/research/R11-gate-v2-knowledge-pack.md` (§5 smart-scan row, §7, invariants 7, 8, 15),
`docs/research/R12c-osquery.md`, `R12d-wazuh.md`, `R13-admin-realtime-remediation.md` (§3),
`R13b-design-discussion.md` (P2, P6), `docs/handoff/PROJECT_CONTEXT.md` §10,
`agent/sentinel/watcher.py`, `agent/sentinel/scanjob.py`, `agent/sentinel/service/worker.py`.

## Allowed paths

New files only: `agent/sentinel/gate_v2/scope.py`, `agent/sentinel/service/usn.py`,
`agent/sentinel/service/procwatch.py`, `agent/sentinel/service/rescan.py`,
`tests/gate_v2/test_scope.py`, `tests/test_service_usn.py`, `tests/test_service_procwatch.py`,
`tests/test_service_rescan.py`. Everything else is read-only; nothing is wired.

## `gate_v2/scope.py`

`discover(profile, sources) -> Iterator[Target]` plus a `ScopeReport` of source-entry coverage:
every discovered entry, resolved or unresolved, with typed reasons; a missing key is distinct
from access denied. Bounded: entries, bytes, depth, time. Each source is an injected callable,
so all logic is tested without a real machine; real implementations follow:

* watched folders, user and Common Startup (walk without following reparse points);
* Run and RunOnce, HKCU and both HKLM views (reuse `watcher.read_run_entries`, `command_files`);
* scheduled tasks: `%SystemRoot%\System32\schtasks.exe /query /xml ONE` by absolute path, parsing
  executable actions from the XML with a size cap; an unreadable task is a counted gap;
* running processes: `CreateToolhelp32Snapshot`, `QueryFullProcessImageNameW` with
  `PROCESS_QUERY_LIMITED_INFORMATION`; a denied or vanished process is counted;
* admin sources for A4, used only when the caller can read them: other users' Run keys through
  `HKEY_USERS`, service `ImagePath` values, and WMI event consumers through a fixed read-only
  PowerShell query by absolute path. Denied is a gap, never empty.

Dedupe by volume and file id, one scan per identity; hard links collapse. Sentinel's own data is
excluded before queueing, by file identity of the data root, not by string prefix (RT-003, RT-007).
Deep profile: all fixed drives, skipping reparse points, resumable from a cursor, never lowers any
threshold. RT-024: junction skipped, long path, denied directory all appear in the report.

## `service/usn.py`

Pure parsers for `USN_RECORD_V2`, `V3` with bounds on every length (hostile records never raise),
`USN_JOURNAL_DATA`, reason flags. `JournalCursor` persisted by an injected store. A `read_batch`
wrapper over `DeviceIoControl` (`FSCTL_QUERY_USN_JOURNAL`, `FSCTL_READ_USN_JOURNAL`) behind an
injected device. Journal id change, `USN_JOURNAL_NOT_ACTIVE`, wrapped cursor, access denied each
give a typed gap that demands reconciliation, never silence. Path resolution from file reference
behind an injected resolver; rename chains handled.

## `service/procwatch.py`

500 ms sampled snapshot (R13b P6): new `(pid, creation time)` pairs resolve to image path and
identity, then a bounded queue of scan targets. Reports `process_observation=sampled`, poll
duration, failed polls, inaccessible images, exits before resolution, largest gap. PID reuse must
not reuse a cached result. Injected snapshot and clock; one real, unelevated test.

## `service/rescan.py`

Rescan queue for downloads: when signatures change or a downloaded file first runs. Keeps identity
and origin zone in a bounded store behind an injected interface; expiry, dedupe, generation
comparison. A URL or path hint never authorises an action.

## Rules

Python 3.12+, typed, stdlib only, comments explain why, LF. Harmless synthetic data. Every bound hit
is reported. Nothing may read as clean because a source failed (invariants 1, 7, 15).

## Your answer

English, concise: files and line counts, API, test per requirement, what Claude must wire, what only
an elevated run can prove.
