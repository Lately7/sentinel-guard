# Codex round R13b — design discussion with Claude (read-only)

You wrote R13 (`docs/research/R13-admin-realtime-remediation.md`). The owner
asked Claude and you to **discuss the design** before any code. Claude adopted
R13's direction but challenges the points below. Answer each point: **agree /
disagree / modify**, your reasoning with sources (repo file:line, official
Microsoft/Python docs; web search for documentation only, no downloads), and
the concrete decision you propose. Where you and Claude still disagree, say so
plainly — the owner decides. Do not re-argue R11 or milestones 1–2.

Read-only: no file changes. English. Claude saves your answer as
`docs/research/R13b-design-discussion.md`.

## Constraints you must design within

* `AGENTS.md`: engine, `db.py`, `nativehost.py`, `feeds.py` are **stdlib-only**;
  `watchdog`, `pystray`, `Pillow`, `yara-x` are the only optional packages.
  Adding `pywin32`/`comtypes` or a third-party service wrapper (NSSM, WinSW)
  is a new dependency the owner must approve — propose it only if stdlib +
  `ctypes` is clearly worse, and say what it costs.
* Claude never elevates; the owner runs elevated installs and acceptance
  checks. Everything else must be testable unelevated.
* No kernel driver. No Defender setting changes.

## Points

**P1 — Service host in Python.** A Windows service needs
`StartServiceCtrlDispatcherW`/`RegisterServiceCtrlHandlerExW`. Options:
(a) `ctypes` service dispatcher in our own code, (b) `pywin32`
(`pythonservice.exe`), (c) a tiny wrapper we would have to build (C) or
download, (d) **a Task Scheduler task running as SYSTEM with a boot trigger**
(`TASK_LOGON_SERVICE_ACCOUNT`, `onstart`) — R13 compared only a *logon*
task. (d) also starts before logon and needs no service plumbing; the
watchdog/restart behaviour would come from task settings. Compare (a)–(d) on
pre-logon start, crash restart, stop/shutdown notification (we need a clean
stop for the action barrier), SCM-level ACLs (who may stop it), and risk.
Pick one.

**P2 — LocalSystem vs. service SID.** Opening `\\.\C:` for
`FSCTL_READ_USN_JOURNAL` requires administrative rights on the volume
handle, so a non-admin virtual account likely cannot read the journal; the
same goes for other users' profiles. Is "thin LocalSystem service with
trimmed privileges (`SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`)" therefore the
only practical choice, or would you split a separate tiny USN reader? Decide.

**P3 — The pipe is an attack surface for user-level malware.** Any process
running as the logged-on user can connect to the pipe exactly like our tray.
Through it, malware could ask the service to *turn protection off*, *trust a
host*, *restore a file from quarantine*, *add an exclusion* or *approve a
repair*. Caller-SID checks do not help — malware has the same SID. Propose
the rule: which commands any interactive user may send (status, scan
requests, download hints), which need an **elevated confirmation** (e.g. a
UAC-launched consent helper whose high-integrity token the service verifies,
or the secure desktop), and what the browser native host may send at all.
How does this interact with today's features: "Luôn tin cậy" from the warning
page, restore from the tray, the on/off switch? Note the earlier rule
"browser-supplied path or URL never authorises privileged mutation" (R13 §1).

**P4 — Where each engine runs.** R13 §2 sends ClamAV through a "separately
brokered operation" and gives the worker no network. Concretely: the clamd
client only streams bytes over localhost TCP and parses a one-line reply;
Defender is `MpCmdRun` with a path. Proposal from Claude: core/archive/PE/
YARA-X in the restricted worker; clamd INSTREAM and Defender invocation from
the service with strict reply parsing (R8c) and no file parsing. Agree?
What exactly does the service read from file content in that case?

**P5 — Worker mechanics in stdlib Python.** `CreateProcessAsUserW` with a
restricted, low-integrity token (needs `SeAssignPrimaryTokenPrivilege`, which
LocalSystem has), `DuplicateHandle` of a read-only file handle into the
worker, `msvcrt.open_osfhandle` on the worker side, Job Object with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and memory caps — all via `ctypes`.
Persistent worker pool (2, max 4) recycled after N files or memory growth, vs.
one process per file (Python start-up cost). Does a low-integrity Python
process load `yara_x` and our modules from Program Files without extra ACL
work? Can the worker run *without* a writable temp dir? Give the design and
the failure modes (worker crash = typed `ERROR`, never clean).

**P6 — Process-start observation in stdlib Python.** Real-time ETW
consumption needs `StartTraceW`/`EnableTraceEx2`/`OpenTraceW`/`ProcessTrace`
with callbacks via `ctypes` — feasible but heavy; WMI
`Win32_ProcessStartTrace` needs COM (`comtypes`/`pywin32`, not stdlib).
Alternative: poll a process snapshot (`CreateToolhelp32Snapshot` or
`NtQuerySystemInformation`) every 500 ms — loses short-lived processes but is
simple. Which do you recommend for A5, and how is loss reported?

**P7 — Who may change settings, and where data lives.** Service data in
`%ProgramData%\SentinelGuard` with an ACL (SYSTEM + Administrators full,
users none or read?), quarantine store there; per-user UI preferences stay in
`%LOCALAPPDATA%`. `SENTINEL_HOME` stays for tests and dev mode only. Is the
current SQLite DB shared by service and tray today (`db.py`)? After the
split, only the service writes; the tray reads through IPC. Agree? What about
the browser native host, which today opens the DB directly
(`nativehost.py`)?

**P8 — Dev and test mode without admin.** Claude needs to run every
milestone's tests unelevated. Proposal: the "service" core is a plain Python
object (`ServiceCore`) driven by an in-process or same-user pipe in tests;
the Windows-service shell, privilege trimming, pipe DACL and worker token are
thin layers tested only by the owner's elevated acceptance script
(`tools/admin_acceptance.ps1`). Agree? List what the owner's script must
check, in order, with expected outputs.

**P9 — Migration and Defender coexistence.** Today: per-user tray at logon
(HKCU Run) + per-user native host (`install.py:53-80`). After: service + tray
+ native host. How do we migrate without a protection gap, and how do we
uninstall cleanly? Defender stays on (owner's machine has Defender passive
with Malwarebytes active, see `REVIEWS.md` round 1): if Defender or
Malwarebytes quarantines the same file first, what does our repair/quarantine
step do (`file vanished` ≠ failure)? Avoid fighting other security products.

**P10 — Order.** R13 puts Gate v2 M3–M6 before A1. Claude's view: A1 (IPC
schema + `ServiceCore` + mock pipe, no privileges) can run **in parallel**
with M3 because the files do not overlap, and P3's command-authorisation
model should be fixed before M7 wires actions. Agree, or keep strict order?

## Your answer

For each point: verdict, reasoning with sources, decision. Then a short
"Agreed design" summary (≤ 25 lines) and a list "Open for the owner" with
the options and your recommendation for each.
