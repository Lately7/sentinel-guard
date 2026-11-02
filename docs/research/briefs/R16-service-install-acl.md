# Codex research round R16 — installing the privileged service safely (A3)

Read-only research round. Do not create, modify or delete any file. Answer in English;
Claude saves your answer as `docs/research/R16-service-install-acl.md` and writes the code.

## Context

Sentinel Guard is the repository owner's own Windows 11 anti-malware prototype. Read:
`docs/research/R13-admin-realtime-remediation.md`, `docs/research/R13b-design-discussion.md`
(P1, P2, P3, P5, P7, P8, P9), `docs/handoff/NEXT_SESSION.md` §5 item 3, and
`agent/sentinel/service/` (`host.py`, `winpipe.py`, `worker.py`, `core.py`, `authz.py`,
`protocol.py`, `client.py`), `agent/sentinel/install.py`, `agent/sentinel/config.py`.

**The problem to solve first.** The code runs from `.venv` under
`C:\Users\lately07\Desktop\Folder Group\sentinel-guard`, which the signed-in user can write.
A LocalSystem service that imports Python from there hands SYSTEM to any process of that
user. Python is 3.15.1 with `yara-x`. Project rules: no new dependency without owner
approval (`pywin32`, `comtypes` are not approved), no downloads by Claude, argv arrays with
`shell=False`, Claude never elevates: the owner runs every elevated command. Defender
settings are never touched.

## Questions

1. **Install layout.** Exactly what must be copied to an admin-only location (for example
   `%ProgramFiles%\SentinelGuard`) so that the service, the worker and the consent helper
   import nothing user-writable: base interpreter, stdlib, DLLs, `python315._pth` or
   equivalent, `-I -B`, `.pyc` handling, `yara_x` native module, how `sys.path` is proved.
   Copying from the existing base interpreter, not downloading. Every way user-writable
   code can still enter: `PATH`, DLL search order, `PYTHON*` variables, `PYTHONPYCACHEPREFIX`,
   `.pth` files, `__pycache__`, current directory, `SENTINEL_HOME`, registry
   `PythonPath`, `HKCU` keys read by a SYSTEM process. For each, the mitigation and a check
   the acceptance script can run. Update path: how a later version replaces the files
   without opening a window.
2. **Service registration via `ctypes`.** `OpenSCManagerW`, `CreateServiceW` (binary path
   quoting, account, start type), `ChangeServiceConfig2W` for failure actions, description,
   `SERVICE_CONFIG_SERVICE_SID_INFO`, `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`,
   `SERVICE_CONFIG_PRESHUTDOWN_INFO`, delayed auto-start. `SetServiceObjectSecurity` with an
   exact SDDL string: SYSTEM and Administrators control, ordinary users query only.
   `DeleteService`, stop before delete, marked-for-deletion handling. Exact structures for
   64-bit, access rights, return codes.
3. **ProgramData layout and ACLs.** Layout for DB, feeds, policy state, repair journal and
   quarantine per R13b P7. **Pre-creation attack:** `%ProgramData%` lets users create
   folders, so a user process can make `SentinelGuard` first with its own ACL or a reparse
   point inside. Exact safe creation order: check for reparse points, take ownership,
   protected DACL, verify after. Exact SDDL. What must be checked at every service start,
   and what to do on failure (refuse to start, typed status). Worker read access for
   restricted-token SIDs per P5.
4. **UAC consent helper.** `ShellExecuteW`/`ShellExecuteExW` with `runas` launched from an
   unelevated tray: how the helper is found (absolute path under the protected install, never
   from the caller), what the UAC prompt displays for `python.exe` versus a small launcher,
   and whether a manifest is needed. Tk from an elevated process on the normal desktop:
   risks from a same-user unelevated process (UIPI, input injection, window messages, shatter
   style) and what mitigates them. Passing the plan id on the command line: what an
   attacker gains from starting the helper with an id of its choice, and how the fetch-plan
   step stops text spoofing. Timeouts, cancellation, one helper per plan, wording rules for
   Vietnamese text built by the service.
5. **`tools/admin_acceptance.ps1`.** Turn R13b P8's eight ordered checks into a concrete
   script outline: how it refuses to run unelevated, how each check obtains its evidence
   (`sc.exe qsidtype`, `sc.exe sdshow`, `Get-Acl`, an unelevated test client started with a
   medium-integrity token from an elevated script, and how), expected output per check, and
   cleanup. It must not change Defender settings; it must run against disposable state.
6. **Migration and uninstall.** R13b P9 action lease between the old tray and the new
   service: where the lease lives, who can write it, crash behaviour. Uninstall order and
   what is retained by default. Native-host manifest and HKCU Run entries during handoff.

## Deliverable

A recommended design, then per question: exact API sequence, structures and constants,
SDDL strings explained term by term, failure handling, and a test that can run **unelevated**
beside a check only the owner's elevated script can do. Flag anything needing an owner
decision. Cite Microsoft Learn or other primary URLs for every external claim and `path:line`
for code. Separate documented fact from inference. Never claim a command ran unless you ran it.
