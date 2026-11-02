> **Claude note (2026-11-02, night).** Design discussion requested by the owner ("thảo luận với Codex").
> Claude's 10 challenges: `docs/research/briefs/R13b-design-discussion.md`; Codex's answer below
> (gpt-6-sol, high, read-only, web search for documentation only). **Outcome:** converged.
> Codex accepted Claude's points P1 (boot task considered; still a service, own `ctypes` shell),
> P3 (pipe is reachable by user-level malware → elevated, plan-bound confirmation for
> security-weakening commands; native host read/hint-only), P4 (engine placement), P6 (process
> snapshots before ETW), P7, P8, P10 (A1 in parallel with G3–G6). Codex corrected Claude on P5:
> a restricted copy of the caller's own token does not need `SeAssignPrimaryTokenPrivilege`.
> **Claude reservation (for the A2/G5 brief):** P4's "protected snapshot" for Defender would write a
> copy of possibly malicious content to disk where Defender/Malwarebytes may quarantine it
> themselves; Claude prefers the before/after identity check with an `unbound` result on mismatch.
> Owner questions: see the end of this document and `docs/handoff/NIGHT_REPORT.md`.

# R13b design discussion

**Recommendation:** use a thin LocalSystem Windows service with a `ctypes` service shell, an unelevated tray and native host, and a restricted scan worker. I agree with Claude’s proposed engine placement and with starting the unprivileged A1 contract work alongside G3. I would change R13’s A5 plan: start with process snapshots and make ETW a later, measured enhancement.

## P1 — Service host in Python: **Modify R13**

R13 compared a service with a *logon* task. Claude is right that a SYSTEM task with a boot trigger can also start before logon. Microsoft says boot tasks start when the Task Scheduler service starts, and supports restart-on-failure settings. It does not give the process the service control handler needed for our stop barrier; Task Scheduler also stops long-running tasks after 72 hours by default unless configured otherwise. A Windows service can report `STOP_PENDING`, handle stop and preshutdown controls, and use SCM recovery actions. [Boot trigger](https://learn.microsoft.com/en-us/windows/win32/taskschd/boottrigger), [task restart setting](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-restartonfailure-settingstype-element), [task time limit](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks), [service state transitions](https://learn.microsoft.com/en-us/windows/win32/services/service-status-transitions), [service recovery and preshutdown](https://learn.microsoft.com/en-us/windows/win32/services/service-changes-for-windows-vista).

| Option | Pre-logon and restart | Stop, ACL, and main risk |
|---|---|---|
| **(a) Own `ctypes` service shell** | Yes; SCM failure actions restart it. | SCM stop/shutdown notification supports the action barrier. Service DACL can deny ordinary users `SERVICE_STOP`. Risk: Win32 callback, structure, and lifecycle mistakes in our code. |
| **(b) `pywin32` / `pythonservice.exe`** | Same service capabilities. | Less service boilerplate, but a new runtime dependency and privileged host to package and update. Owner approval required. |
| **(c) C or downloaded wrapper** | Same if the wrapper implements the protocol correctly. | Adds a build/toolchain or third-party binary and another privileged component to audit and update. Owner approval required for a third-party wrapper. |
| **(d) SYSTEM boot task** | Yes; task settings can retry failure. | No native SCM stop/preshutdown handler, service SID, required-privileges configuration, or service-object `SERVICE_STOP` ACL. A separate graceful-stop protocol and careful task settings would be needed. |

**Decision:** choose **(a)**. Keep callbacks minimal: signal `ServiceCore` to stop, report pending status, wait for its action barrier, then report stopped. Give SYSTEM and Administrators service control rights; ordinary users get status/query rights only. Microsoft documents `SERVICE_STOP` as a separately controlled service right. [Service functions](https://learn.microsoft.com/en-us/windows/win32/services/service-functions), [service security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). I do not yet see a clear benefit that justifies the new dependencies in (b) or (c).

## P2 — LocalSystem and service SID: **Modify R13**

A **service SID is not an alternative logon account**. It identifies a service for ACL purposes; it can be added to a LocalSystem service token. LocalSystem has broad local access through its SYSTEM and Administrators SIDs. Required-privileges configuration trims named token *privileges*, but does not remove access those SIDs receive from object ACLs. [LocalSystem account](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account), [service isolation](https://learn.microsoft.com/en-us/windows/win32/services/service-changes-for-windows-vista).

USN operations use a volume handle. Microsoft documents the handle and notes administrator rights for non-programmatic journal operations; the exact programmatic read capability should be verified on the owner’s machine, as R13 proposed, rather than asserted from that note alone. Cross-user profile access also makes a non-admin account a poor baseline. [Volume handle](https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-a-volume-handle-for-change-journal-operations), [journal operations](https://learn.microsoft.com/en-us/windows/win32/fileio/creating-modifying-and-deleting-a-change-journal).

**Decision:** one thin LocalSystem service, with its service SID used on its private objects and an owner-tested required-privileges list. Do not add a second USN-reader service yet: it would still need privileged volume access and another IPC boundary while leaving cross-user enumeration and remediation in the main service. Record denied volumes and profiles as coverage gaps. No `SeDebugPrivilege`, backup, or restore privilege by default; include only privileges demonstrated necessary by acceptance checks.

## P3 — Pipe command authorization: **Agree with Claude’s challenge; modify R13**

R13’s SID/session checks establish *which user* sent a request, not that the request came from our tray. User-level malware has the same SID. Pipe impersonation is still useful for checking whether that user may read a requested file; Microsoft warns that an impersonation failure must fail closed. [Named-pipe impersonation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient). Current code permits the native host to write the allowlist (`agent/sentinel/nativehost.py:177-185`), the tray to restore and trust a quarantined hash (`agent/sentinel/tray.py:340-354`), and the tray to switch real-time protection off (`agent/sentinel/tray.py:143-160`).

**Decision:**

| Caller | Allowed requests |
|---|---|
| Any authenticated local interactive user | Bounded status and user-scoped history; URL/blocklist lookup; scan requests for files that user can read; download-complete hints; cancellation of that caller’s pending *manual* scan. These requests cannot supply a verdict or authorize an action. |
| Browser native host | `hello`, URL/blocklist/allowlist reads, bounded web telemetry, and download hints only. No settings, allowlist writes, restore, delete, exclusion, repair approval, or service stop command. |
| Elevated consent helper | A specific, freshly displayed action plan: disable protection, persistent host trust, exclusion, quarantine restore/delete, or repair approval. The service checks the connected token’s admin membership and high integrity, binds a short-lived plan nonce to the original user/session and exact plan version, and rechecks object identity before acting. |

The helper must be installed in an admin-writable location and fetch the plan from the service; it must not display text supplied only by a low-integrity request. UAC can launch a separate elevated helper, and its prompt normally appears on the secure desktop. This protects against an unelevated process silently issuing an admin command; it cannot protect against malware that is already elevated. [UAC helper approach](https://learn.microsoft.com/en-us/windows/win32/secbp/running-with-administrator-privileges/), [secure desktop](https://learn.microsoft.com/en-gb/windows/security/application-security/application-control/user-account-control/how-it-works).

“**Luôn tin cậy tên miền**” on the warning page must open this confirmation flow before changing the service’s persistent allowlist. “Open once” can remain a tab-scoped browser choice, with no service policy mutation. Tray restore and the service real-time off switch need the helper. The extension’s own `set_enabled` switch is currently browser-local (`extension/src/background.js:343,395-445`); it must be labelled and reported as an **extension-only** control. A user-writable extension cannot claim the same tamper resistance as service protection. A browser-supplied path or URL remains a hint, never authority for privileged mutation, as R13 §1 and §4 require.

## P4 — Engine placement: **Agree, with an identity condition**

Claude’s split is sensible: core/archive/PE/YARA-X parse in the restricted worker; the service brokers clamd `INSTREAM` and invokes Defender with argv and `shell=False`. Current clamd code streams bounded chunks and parses a short reply (`agent/sentinel/engine/clamav.py:184-225,312-317`). Defender currently receives a path, uses `-DisableRemediation`, and treats a vanished file as an error (`agent/sentinel/engine/defender.py:107-133`). R8c explains why `OK` does not prove recursive coverage (`docs/research/R8c-clamav-signatures-clamd.md:14,175-184`).

**Decision:** the service may read **only bounded raw chunks** from its already-open file handle to stream to clamd, plus file identity/size metadata and bounded clamd/Defender replies. It must not run ZIP, PE, document, YARA, or content-rule parsing. Hashing or file-type inspection belongs in the worker. The service should treat clamd’s reply as a strict, size-limited protocol result, not file content.

Defender’s path interface creates an identity problem: a pathname can change between the worker’s read and `MpCmdRun`. Prefer an identity-bound protected snapshot if Defender must contribute evidence to that same generation. Otherwise, compare identity before and after and mark its result **unbound/unknown** if the binding cannot be proved. A Defender result about a different generation cannot authorize our quarantine.

## P5 — Restricted worker: **Modify R13 and Claude’s privilege assumption**

Microsoft says `CreateProcessAsUserW` may require `SeIncreaseQuotaPrivilege`, but **does not require `SeAssignPrimaryTokenPrivilege` when given a restricted version of the caller’s primary token**. Thus that privilege should not be retained merely because the launcher uses this API. [CreateProcessAsUser](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera), [restricted tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens).

**Decision:** start two persistent workers, cap at four, and recycle after a measured file count, memory growth, crash, or policy generation change. Launch suspended with a restricted SYSTEM-derived token, low integrity, fixed protected interpreter path, `-I -B`, sanitized environment, and a Job Object with process/memory limits and `KILL_ON_JOB_CLOSE`. Pass only the intended read-only file handle and IPC handles; use explicit handle inheritance or duplication into the known worker process. Python `-I` excludes user import paths and Python environment variables; `-B` prevents attempted bytecode writes. [Python command line](https://docs.python.org/3.12/using/cmdline.html), [handle inheritance](https://learn.microsoft.com/en-us/windows/win32/procthread/inheritance), [job limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information).

A low-integrity process can generally **read** medium-integrity Program Files objects if the DACL permits it, but a *restricting SID* adds another access check. Therefore Python, our modules, DLLs, and `yara_x` may need explicit read/execute ACL entries for the worker’s restricting SID. Do not use a broadly useful restricting SID just to avoid this work. They must remain non-writable by users and the worker. Low integrity blocks ordinary write-up; it does not itself prevent reads. [Mandatory integrity control](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/25fa6565-6cb0-46ab-a30a-016b32c4939a), [restricted-token checks](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens).

Try a no-temp worker first, but do **not** promise it works for every Python/native-library path. If needed, provision a per-worker scratch directory with a low-integrity label and a narrow ACL; never give the worker write access to installed code, rules, or the quarantine store. A restricted token plus Job Object does **not** enforce “no network” by itself. The worker contract can avoid network APIs now; an OS-enforced network ban would require a separately approved isolation mechanism. Worker launch/import failure, crash, timeout, OOM, malformed reply, or changed file yields typed `ERROR` or incomplete coverage, **never clean**.

## P6 — Process-start observation: **Modify R13**

R13 proposed ETW first (`docs/research/R13-admin-realtime-remediation.md`, §3; `docs/ROADMAP.md:43-45,59`). ETW’s real-time controller/consumer and callbacks are feasible through `ctypes`, but substantial code at this privilege boundary. `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` has a documented, simpler process enumeration API. [Tool Help snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot), [ETW consumer](https://learn.microsoft.com/en-us/windows/win32/etw/consuming-events).

**Decision:** for A5, poll process snapshots every **500 ms**, then resolve new PIDs with creation time and image identity before queuing scans. Record poll start/end, duration, failed polls, inaccessible images, process exits before resolution, and the largest interval between successful snapshots. Report `process_observation=sampled`, with “short-lived processes may be missed”; no numeric “events lost” claim is possible from polling. On a failed/late poll, report a coverage gap for that interval. Add ETW only if owner-machine measurement shows the missed-process limitation merits its complexity. ETW would then report `EventsLost` and `RealTimeBuffersLost`, which Microsoft exposes as session statistics. [ETW statistics](https://learn.microsoft.com/en-us/windows/desktop/ETW/event-trace-properties).

## P7 — Settings and data: **Agree, with one clarification**

Today the tray and native host create **separate `Database` connections to the same per-user path**, rather than sharing one connection: `config.db_path()` uses `%LOCALAPPDATA%\SentinelGuard` or `SENTINEL_HOME` (`agent/sentinel/config.py:20-44`); tray construction is at `agent/sentinel/tray.py:51-60`; native host construction and direct DB operations are at `agent/sentinel/nativehost.py:21-25,57-70,93-102,177-185`. The prior DB incident is documented at `REVIEWS.md:6-20`.

**Decision:** service-owned DB, feeds/policy state, repair journal, and quarantine under `%ProgramData%\SentinelGuard`; SYSTEM and Administrators full access, ordinary users **no direct read or write**. The store includes URLs, file paths, and quarantined content, so tray status/history should be filtered through IPC by caller and session. Per-user UI preferences remain in `%LOCALAPPDATA%`. Ignore `SENTINEL_HOME` in installed service mode; retain it for tests/dev mode. Only the service writes the service DB. Tray, native host, CLI, and report paths use versioned IPC; the native host no longer imports `Database` or `Scanner` for live operation. Feed updates are requested through IPC but performed and committed by the service.

## P8 — Unelevated development: **Agree**

Make `ServiceCore` a plain Python object with injected storage, scanner, authorizer, clock, and action interfaces. Test it in-process and through a same-user test pipe. Unit-test service-shell state transitions, token-building arguments, and ACL construction with mocks unelevated. These mocks do not establish that Windows enforced the ACL or token. The owner alone runs `tools/admin_acceptance.ps1`, consistent with `docs/ROADMAP.md:55-63` and `AGENTS.md`’s test-result rule.

**Proposed owner-script order and expected results** (these are acceptance targets, not results already run):

1. **Preflight:** confirm elevated token, installed protected paths, required binaries, and test fixtures. Output `PASS preflight`; otherwise stop before mutation.
2. **Install/configure:** register and start service; query SCM account, automatic start, failure actions, service SID, required privileges, and service DACL. Output `PASS service_config` and `RUNNING`; ordinary user cannot request `SERVICE_STOP`.
3. **Storage/pipe:** query ACLs and use an unelevated test client. Expected: status and own-file scan accepted; direct ProgramData DB/quarantine read denied; wrong-user, remote, oversized, malformed, and unelevated mutation requests denied.
4. **Worker:** inspect token integrity/restrictions and Job Object; scan harmless test-only markers. Expected: installed code loads, no write to installed code or store, intended handle readable, injected crash/OOM/timeout reported `ERROR`, worker tree gone after broker stop.
5. **USN and source access:** read a disposable NTFS-volume cursor, restart and resume; simulate invalid cursor; enumerate harmless cross-user test source. Expected: cursor continuity or explicit reconciliation/denial, never silent clean.
6. **Observation/download:** run benign process churn and completed-file tests. Expected: sampled-process counters and interval gaps reported; URL/path hints alone cause no privileged action.
7. **Action barrier/recovery:** use a harmless test-only detection, stop during action, restart, and inspect journal. Expected: no new action after stop barrier, prepared action reconciled, no double quarantine.
8. **Coexistence and lifecycle:** verify Defender mode is observed without changing it; test service crash recovery, clean stop, migration handoff, and uninstall on disposable state. Expected: recovery status, no duplicate active actor, browser/tray disconnection reported, installed binaries removed only after stop, retained quarantine/data reported.

## P9 — Migration and Defender coexistence: **Modify R13**

Current install is per-user HKCU native-host registration plus HKCU Run tray (`agent/sentinel/install.py:53-100`). The native host and tray can both scan and act today (`agent/sentinel/nativehost.py:143-159`; `agent/sentinel/tray.py:133-160`). Defender already has a documented passive-mode interaction with Malwarebytes: exit code 2 was once misread as a detection (`REVIEWS.md:57-64`).

**Decision:** ship a transitional legacy tray that understands a machine-wide handoff/action lease. Install and start the new service in **observe-only** mode while the legacy tray remains active; initialize its DB and USN cursor, check IPC and workers, then transfer the action lease at the old watcher’s stop barrier. Activate service actions, reconcile changes since its cursor, switch the tray/native-host clients to IPC, and remove the old HKCU Run entry. Record the handoff interval. USN reconciliation limits missed change *observation*; without a driver, neither old nor new design can promise an absolute prevention gap of zero. The action lease prevents two processes quarantining the same file.

For a file that vanishes before our action, record `externally_removed_or_vanished` with its last known identity and **do not** call it clean or automatically recreate it. If Defender/Malwarebytes history confirms its own quarantine, record external remediation as observed; do not restore, re-quarantine, change AV settings, or retry against a replacement at the same path. The service must revalidate identity immediately before any mutation. On uninstall: stop through SCM and complete the barrier, terminate workers, remove service and per-user registrations, then remove installed code. Retain quarantine, DB, and repair journal by default for explicit later owner disposition; never auto-restore quarantined files.

## P10 — Order: **Agree with Claude; modify R13**

A1’s schema, command authorization, `ServiceCore`, and mock pipe can proceed alongside G3 because they define the boundary without depending on final detection internals. `docs/ROADMAP.md:52-60` currently orders G3–G6 first; R13 §7 did likewise. P3’s command policy must be fixed before M7/A3 action wiring.

**Decision:** run **A1 contract work in parallel with G3–G6**, with an explicit typed evidence/action interface agreed before either side integrates. A1 must not make privileged mutations or assume a provisional scan verdict is final. A2 integration follows the typed gate adapter; M7/A3 follows the authorization model and worker identity tests. This is a change to R13’s strict order, and I agree with Claude on it.

## Agreed design

1. Thin LocalSystem service; ordinary tray and native host stay unelevated.
2. Own `ctypes` SCM shell; service SID and tested privilege trimming.
3. Service-owned ProgramData state and quarantine; clients use versioned IPC.
4. Read-only interactive requests are scoped; security-weakening or repair requests need elevated, plan-specific confirmation.
5. Native host sends lookups, telemetry, and download hints only.
6. Restricted low-integrity workers parse untrusted file formats and YARA-X; worker failure is never clean.
7. Service streams bounded raw bytes to clamd and brokers Defender, with evidence bound to a file generation.
8. A5 starts with sampled process snapshots and explicit coverage gaps; ETW remains an option.
9. Service and legacy tray transfer the action lease during migration; other AV actions are observed without interference.
10. A1 begins alongside G3–G6; privileged action wiring waits for the command policy and typed gate interface.

## Open for the owner

- **Persistent “Always trust” experience:** require elevated confirmation for a service-wide allowlist change (**recommended**), or keep only a browser-local trust choice with explicitly weaker protection. The current immediate service allowlist write should end.
- **Blocklisted download URL alone:** warning/browser cancellation and completed-file scan (**recommended**), or retain URL-only automatic file quarantine. The latter conflicts with R13’s rule that browser claims do not authorize privileged mutation.
- **Worker network isolation:** accept a no-network-code contract for the first worker milestone (**recommended, accurately labelled**), or approve a later OS-enforced isolation design and its install/configuration cost.
- **ETW timing:** ship 500 ms snapshot observation first (**recommended**), or fund the larger `ctypes` ETW consumer in A5.
- **Uninstall data:** retain quarantine and repair evidence by default (**recommended**); offer a separate explicit purge after the owner has reviewed it.