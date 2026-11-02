> **Claude note (2026-11-02).** Codex gpt-6-sol, high, read-only with web search. Input to A3. Its citations
> were not re-checked; each API claim must be proved by a test or the owner's acceptance script.

# R16 — safe installation of the privileged service

## Recommended design

Install an **independent, protected Python runtime** under `%ProgramFiles%\SentinelGuard\versions\<version-id>\`. Run the service, worker, and consent helper only from that version. Put service state under `%ProgramData%\SentinelGuard\` with a separate protected ACL. The owner runs the elevated installer and acceptance script; neither development code nor the service elevates itself.

**A3 must not register the current checkout as a LocalSystem service.** In a read-only local inspection, `.venv\Scripts\python.exe -I -B` reported its base executable under the signed-in user’s AppData and still included both `.venv\Lib\site-packages` and the editable checkout’s `agent` directory on `sys.path`. The venv contains `__editable__.sentinel_guard-0.1.0.pth`; `yara_x` includes `yara_x.pyd`. This confirms that `-I -B` alone does not establish the install boundary on this machine. Python documents that `-I` excludes Python environment variables and user site packages, while `._pth` can completely override the Windows import path and suppress `site` processing. [`agent/sentinel/service/worker.py:228-253`; Python command line](https://docs.python.org/3/using/cmdline.html#cmdoption-I), [Python path initialization](https://docs.python.org/3/library/sys_path_init.html).

**Trust limit:** copying bytes from a user-writable interpreter or checkout into Program Files protects them *after* installation; it cannot prove they were trustworthy *before* copying. The owner must approve a reviewed source snapshot or trusted hashes/signatures for the installer, Python runtime, application, and native modules. No download or new dependency is required for the proposed mechanics. This is an inference from the stated source permissions.

## 1. Install layout and import boundary

Use Windows Known Folder APIs for Program Files and Common Application Data instead of trusting `%ProgramFiles%` or `%ProgramData%` from the caller’s environment. Stage into a newly created, admin-controlled version directory, never into a writable checkout, venv, temporary directory, or update cache. The version contains:

```text
versions\<id>\
  python.exe
  pythonw.exe
  python315.dll, python3.dll
  vcruntime*.dll actually required by this interpreter
  python315._pth
  Lib\                 protected standard library
  DLLs\                protected standard-library .pyd files
  app\sentinel\        copied package and package data
  vendor\yara_x\       __init__.py and yara_x.pyd
  vendor\...           only other imported runtime dependencies
```

Copy the existing base interpreter’s required files and the venv’s selected package files as **new files**. Exclude `pyvenv.cfg`, `pip`, development tools, editable-install finders, `.pth` and `.egg-link` files, `sitecustomize.py`, `usercustomize.py`, and all `__pycache__` and `.pyc` files from the source snapshot. Include a dependency only after a protected-runtime import probe proves it is needed; inspect native `.pyd` dependencies as well. The current package declares YARA-X and UI packages as optional dependencies, and the worker imports YARA-X through Gate v2 (`pyproject.toml:11-23`, `agent/sentinel/service/workermain.py:17-21,46-51`).

Put this protected `python315._pth` beside `python315.dll`, with only relative, protected entries:

```text
Lib
DLLs
app
vendor
```

Do **not** add `.` or `import site`. The DLL-named `._pth` takes precedence over an executable-named one; with `._pth`, Python ignores registry and environment path entries and does not import `site` unless explicitly directed. This also prevents ordinary `site-packages` `.pth` execution and the Windows `PythonPath` registry paths from entering startup. Keep `-I -B` on every command as defense in depth; `-B` prevents bytecode writes, while excluding source `.pyc` and prohibiting user-writable cache paths prevents loading attacker-controlled bytecode. [Python path initialization](https://docs.python.org/3/library/sys_path_init.html), [Python Windows path rules](https://docs.python.org/3/using/windows.html#finding-modules), [Python bytecode cache behavior](https://docs.python.org/3/library/sys.html#sys.pycache_prefix).

The service command should name the version’s executable absolutely, for example:

```text
"C:\Program Files\SentinelGuard\versions\<id>\python.exe" -I -B -m sentinel.service.entry
```

Give the worker that **same protected executable** and a fixed protected working directory. Replace the development-only `interpreter()`/`bootstrap()` behavior: it currently selects `sys._base_executable` and inserts paths copied from the parent’s `sys.path` into a `-c` program (`agent/sentinel/service/worker.py:228-253`; caller at `agent/sentinel/service/workerclient.py:67-69`). Launch the installed worker directly with `-m sentinel.service.workermain`. The consent helper may use protected `pythonw.exe -I -B -m sentinel.service.consent --plan-id <hex-id>`.

| Entry route | Required mitigation | Acceptance evidence |
|---|---|---|
| `PATH`, current directory, DLL search | Absolute executables; protected working directory; minimal child environment; call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR \| LOAD_LIBRARY_SEARCH_SYSTEM32)` early, and use explicit protected DLL directories for any additional native dependencies. | Record child environment and CWD; attempt import/load with a harmless same-name file in a user directory; inspect loaded module paths. |
| `PYTHON*`, including `PYTHONPYCACHEPREFIX` | Protected `python315._pth`, `-I -B`, sanitized service/child environment. Never use `-X pycache_prefix` in installed mode. | Set hostile environment values in a test invocation; assert unchanged protected `sys.path`, `sys.pycache_prefix is None`, and no writes. |
| `.pth`, editable install, user site, `sitecustomize` | No `import site`; copy no `.pth`; no venv in installed path. | Assert exact `sys.path`; enumerate version tree for prohibited files. |
| `__pycache__`, `.pyc` | Exclude from package; `-B`; protect every import directory. | Enumerate tree; check `sys.dont_write_bytecode`; negative write test. |
| `SENTINEL_HOME` and user settings | Installed service uses fixed ProgramData state and ignores this override. | Start with `SENTINEL_HOME` aimed at a disposable writable directory; assert no service read/write there. |
| Registry `PythonPath` and `HKCU` | `._pth` blocks interpreter path discovery; service configuration must not read HKCU for trusted paths or policy. | Plant a harmless HKCU PythonPath/test preference under a disposable account; verify no module or policy change. |

Windows documents the ordinary DLL search risks and `SetDefaultDllDirectories`; path restriction must also cover dependent DLLs loaded by `yara_x.pyd`. [DLL search order and security](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order), [`SetDefaultDllDirectories`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories). The current worker environment still derives `SystemRoot` from its parent (`agent/sentinel/service/worker.py:178-184`); installed mode should obtain and validate the Windows directory through the OS.

Before starting service work, assert `sys.flags.isolated`, `sys.dont_write_bytecode`, `sys.pycache_prefix is None`, an **exact allowlist** of canonical `sys.path` entries, and protected paths for `sys.executable`, `sys.prefix`, `sentinel.__file__`, `yara_x.__file__`, `python315.dll`, and every loaded native extension. Fail closed with `INSTALL_INTEGRITY` if any path or ACL is wrong. A passing `sys.path` check is evidence of configuration, not proof that the source bytes were trustworthy.

**Update inference:** stage a complete new version in a fresh protected directory; verify hashes, ACLs, reparse status, imports, worker launch, and consent helper there. Close the action barrier and stop the service; use `ChangeServiceConfigW` to point `ImagePath` at the new absolute version; start and health-check it; roll back `ImagePath` to the retained old version on failure. Do not replace files in a running version or switch through a user-writable junction. Remove an old version only after no service, worker, helper, tray, or native host uses it. Microsoft requires the quoted binary path when it contains spaces. [`CreateServiceW`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), [`ChangeServiceConfigW`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw).

## 2. Service registration through `ctypes`

Declare every handle as pointer-sized (`ctypes.c_void_p` or `wintypes.HANDLE`), every `DWORD`/`BOOL` as 32-bit Windows types, and every text API as its `W` variant. Set `argtypes` **and pointer-sized `restype`** before calling. Keep pointed-to strings and arrays alive through `ChangeServiceConfig2W`.

1. `OpenSCManagerW(None, None, SC_MANAGER_CREATE_SERVICE=0x0002)`.
2. `CreateServiceW(scm, "SentinelGuard", display_name, desired_access, SERVICE_WIN32_OWN_PROCESS=0x10, SERVICE_AUTO_START=2, SERVICE_ERROR_NORMAL=1, quoted_absolute_binary_path, ..., lpServiceStartName=None, lpPassword=None)`. `None` selects LocalSystem. Request at least `SERVICE_CHANGE_CONFIG=0x2`, `SERVICE_QUERY_STATUS=0x4`, `SERVICE_START=0x10`, `SERVICE_STOP=0x20`, `DELETE=0x10000`, `READ_CONTROL=0x20000`, and `WRITE_DAC=0x40000` on the returned service handle. [CreateServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), [service rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).
3. Call `ChangeServiceConfig2W` and verify each result with `QueryServiceConfig2W`: level **1** description; **2** failure actions; **3** delayed auto-start; **4** failure-actions flag; **5** service SID; **6** required privileges; **7** preshutdown. Recommend automatic start with delayed auto-start **false** for the agreed early-start objective. Recommend `SERVICE_SID_TYPE_UNRESTRICTED=1` for the service process and a separate restricting-SID check in the worker; `SERVICE_SID_TYPE_RESTRICTED=3` changes the service process token itself and needs a separate capability test. [`ChangeServiceConfig2W`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w), [`SERVICE_SID_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info).
4. Set a minimal *tested* required-privilege multistring, initially `SeImpersonatePrivilege\0SeIncreaseQuotaPrivilege\0\0` only if owner-machine tests show both are needed. `SeChangeNotifyPrivilege` is retained by Windows even if omitted. Do not add debug, backup, restore, or assign-primary-token privilege by assumption. [`SERVICE_REQUIRED_PRIVILEGES_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow), [restricted-token process creation](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens).
5. Configure restart-on-crash actions, for example two `SC_ACTION_RESTART=1` actions with measured delays and a final `SC_ACTION_NONE=0`; `dwResetPeriod=86400`, `lpCommand=None`, `lpRebootMsg=None`. Set `SERVICE_FAILURE_ACTIONS_FLAG.fFailureActionsOnNonCrashFailures=FALSE` so an intentional `STOPPED` after an integrity failure does not restart-loop. Use a preshutdown timeout longer than the measured action barrier, for example 40,000 ms for the present 25-second barrier; report advancing `STOP_PENDING` checkpoints while waiting. [`SERVICE_FAILURE_ACTIONS`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw), [`SC_ACTION`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-sc_action), [failure flag](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flag), [preshutdown timeout](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_preshutdown_info).
6. Convert and apply the service-object DACL with `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `SetServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION=0x4, sd)`, then `QueryServiceObjectSecurity`; free the descriptor with `LocalFree`. Use:

   ```text
   D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0002008D;;;IU)
   ```

   `D:P` is a protected DACL; `A` is allow; `GA` gives SYSTEM (`SY`) and built-in Administrators (`BA`) control. The Interactive Users (`IU`) mask `0x0002008D` is `READ_CONTROL|SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|SERVICE_ENUMERATE_DEPENDENTS|SERVICE_INTERROGATE`. It omits start, stop, pause, change-config, delete, write-DAC, write-owner, and user-defined controls. This is a **service-object** SDDL, distinct from the existing *pipe* SDDL at `agent/sentinel/service/winpipe.py:24-28`. [Service rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), [`SetServiceObjectSecurity`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setserviceobjectsecurity), [SDDL ACE syntax](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings).
7. Close handles on every path. Start only after runtime, state, SID, and ACL verification succeeds.

On x64, the relevant `ctypes.Structure` layouts are:

| Structure | Fields in order | x64 size |
|---|---|---:|
| `SC_ACTION` | `DWORD Type`, `DWORD Delay` | 8 |
| `SERVICE_FAILURE_ACTIONSW` | `DWORD dwResetPeriod`, padding, `LPWSTR lpRebootMsg`, `LPWSTR lpCommand`, `DWORD cActions`, padding, `SC_ACTION* lpsaActions` | 40 |
| `SERVICE_DESCRIPTIONW` | `LPWSTR lpDescription` | 8 |
| `SERVICE_DELAYED_AUTO_START_INFO` | `BOOL fDelayedAutostart` | 4 |
| `SERVICE_FAILURE_ACTIONS_FLAG` | `BOOL fFailureActionsOnNonCrashFailures` | 4 |
| `SERVICE_SID_INFO` | `DWORD dwServiceSidType` | 4 |
| `SERVICE_REQUIRED_PRIVILEGES_INFOW` | `LPWSTR pmszRequiredPrivileges` | 8 |
| `SERVICE_PRESHUTDOWN_INFO` | `DWORD dwPreshutdownTimeout` | 4 |

Assert `ctypes.sizeof()` before installation. These sizes follow the documented field order and 64-bit pointer alignment; the owner’s acceptance run must confirm them on its interpreter.

**Current-code issue:** `host.py` reports `SERVICE_STOPPED` with success even when `service.stop()` returns `False` (`agent/sentinel/service/host.py:93-101`), and its startup exception sets Win32 exit code 1066 without a nonzero service-specific code (`:85-90,136-139`). A3 should preserve a typed failure and never report a completed action barrier when it timed out.

Uninstall uses `OpenServiceW(..., SERVICE_STOP|SERVICE_QUERY_STATUS|DELETE)`, `ControlService(SERVICE_CONTROL_STOP)`, bounded `QueryServiceStatusEx` polling until `STOPPED`, then `DeleteService` and `CloseServiceHandle`. `DeleteService` marks the entry; it disappears only after the service stops and **all** open service handles close. Treat `ERROR_SERVICE_MARKED_FOR_DELETE=1072` as pending deletion, not success and not a reason to recreate immediately. Other useful explicit cases are access denied 5, not installed 1060, not active 1062, and already exists 1073. [`DeleteService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice), [Windows service error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-).

**Unelevated test:** mock each SCM call and assert its arguments, sizes, SDDL, failure cleanup, and stop transitions. **Owner-only check:** query actual configuration and DACL, then have a medium-integrity client prove `SERVICE_STOP` is denied. Mock tests cannot establish Windows enforcement (`docs/research/R13b-design-discussion.md:85-98`).

## 3. ProgramData, ACLs, and pre-creation

Recommended protected tree:

```text
%ProgramData%\SentinelGuard\
  db\
  feeds\
  policy\
  journal\           repair journal and action ledger
  quarantine\
  handoff\           migration lease and epoch
  staging\           protected, non-executable updates
```

Only the service writes the DB. Tray, native host, CLI, and report obtain filtered results through IPC, as R13b P7 decided (`docs/research/R13b-design-discussion.md:79-83`). Installed mode must replace `config.data_dir()`’s user-writable location and `SENTINEL_HOME` override (`agent/sentinel/config.py:20-44`).

For each protected **directory**, use this owner/DACL template, with files inheriting only SYSTEM and Administrators rights:

```text
O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)
```

`O:SY`/`G:SY` set owner/group; `D:P` prevents inherited parent ACEs; `A;OICI;FA` gives inheritable file full access to SYSTEM and Administrators only. `OI` applies to files, `CI` to directories. No ordinary-user ACE is present. Do not use a null DACL: Microsoft notes that a null DACL grants everyone full access. [SDDL ACE syntax](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings), [`SetSecurityInfo`](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo).

The installed **code** tree has a different DACL: SYSTEM and Administrators full, Builtin Users read/execute for ordinary clients, and the service SID read/execute for a worker that uses that SID as a restricting SID:

```text
O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)
                 (A;OICI;FRFX;;;BU)
                 (A;OICI;FRFX;;;S-1-5-80-<resolved service SID>)
```

Resolve the actual SID with `LookupAccountNameW("NT SERVICE\\SentinelGuard")` after registration; do not invent its numeric value. `FRFX` is file read plus execute. No user or worker principal has write access to code. The current worker disables Administrators and privileges but passes **zero restricting SIDs** to `CreateRestrictedToken` (`agent/sentinel/service/worker.py:123-157`). Adding the service SID to `SidsToRestrict` makes Windows perform a second access check: installed code can be read, while ProgramData’s SY/BA-only DACL denies direct worker reads. Low integrity supplies a further write barrier. Test the actual `TokenRestrictedSids` and positive/negative opens; do not infer restriction from `CreateRestrictedToken` succeeding. [Restricted tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens), [mandatory integrity control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control).

**Pre-creation procedure:** treat an existing `%ProgramData%\SentinelGuard` owned or controlled by an ordinary user as hostile. Do not recursively “fix” it in place: changing its DACL cannot revoke an attacker’s already-open write handle, and a child may be a junction or other reparse point. The safe default is `INSTALL_PATH_OCCUPIED` and an owner-supervised removal or move of that *specific* object without following reparse points, followed by fresh creation. For a fresh install:

1. Open and verify the real ProgramData parent; check that ordinary users cannot delete/replace a protected child through `FILE_DELETE_CHILD` on the parent.
2. Inspect the exact target name with `CreateFileW(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT)` if it exists. Reject any reparse tag, unexpected owner, unsafe DACL, file type, or prior untrusted contents.
3. Create a **new** root with `CreateDirectoryW` and a supplied protected security descriptor; open it without following reparse points, set/confirm owner and protected DACL on that handle with `SetSecurityInfo(SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION, ...)`, then verify its file ID, final path, owner, DACL, and reparse attributes. `SetSecurityInfo` returns a Win32 error code directly, unlike BOOL APIs.
4. Create each child with its final ACL before writing data. Copy contents into new files; reject links, reparse points, unexpected hard links, or already-existing names. Verify every object after creation.
5. On each service start, recheck the Program Files version and all critical ProgramData directories, DB, policy, journal, and quarantine objects **before opening them for normal use**. Check owner, effective write access, protected/inherited DACL expectations, file IDs/final paths, and reparse status. On failure, refuse active service startup and publish `INSTALL_INTEGRITY` or `STATE_ACL_UNSAFE` through SCM/event/status evidence; do not silently recreate state or scan it as trusted.

Handle-based security operations and opening reparse points without following them are documented Windows behavior. The refusal to reclaim an attacker-created tree automatically is a safety inference from the open-handle and path-race threat. [Directory handles](https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-a-handle-to-a-directory), [reparse operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-operations), [`SetSecurityInfo`](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo).

**Unelevated test:** build a disposable pre-created directory and junction fixture under a user-writable test root; the installer’s *pure validation* must classify it unsafe without traversing it. **Owner-only check:** perform the real ProgramData pre-creation test on a disposable name and confirm fresh protected creation and medium-token access denial.

## 4. UAC consent helper

From the unelevated tray, call `ShellExecuteExW` with `lpVerb="runas"`, `lpFile` set to the **absolute protected** `pythonw.exe` or protected launcher, `lpParameters` containing only fixed flags/module and a validated hexadecimal plan ID, and `lpDirectory` set to the protected version directory. `SEE_MASK_NOCLOSEPROCESS=0x40` supplies a process handle for a bounded wait and exit result; close it. Handle `ERROR_CANCELLED` as a normal denial and leave the plan unapproved. Do not accept a helper path, module name, or command line from the caller. [`ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw), [`SHELLEXECUTEINFOW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow).

With direct `python.exe`/`pythonw.exe` elevation, the UAC prompt identifies the **Python executable and its publisher/signature**, not “Sentinel Guard”; exact text depends on that binary’s version resources and signature. A small Sentinel-specific launcher with its own manifest and signing would give a clearer prompt, but requires an owner-approved build/signing route. The `runas` verb can request elevation without a custom manifest; a launcher intended only for elevation should explicitly declare `requireAdministrator`, `uiAccess="false"`. A manifest does not bypass consent. [Administrator broker model](https://learn.microsoft.com/en-us/windows/win32/secauthz/administrator-broker-model), [application manifests](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests), [UAC behavior](https://learn.microsoft.com/en-us/windows-server/security/user-account-control/how-user-account-control-works).

I recommend a small `ctypes` native confirmation dialog instead of elevated Tk. If Tk is used, its Tcl/Tk libraries, packages, startup scripts, and environment-derived paths must all come from the protected runtime. An elevated helper’s dialog appears on the ordinary desktop **after** the secure-desktop UAC prompt. UIPI blocks ordinary medium-integrity `SendInput`, hooks, and many window-message attacks against a high-integrity window, but the ordinary desktop is still vulnerable to look-alike windows and misleading foreground context; it is not a secure desktop for plan text. Keep `uiAccess=false`, show a fixed title and service-built summary, and require a fresh explicit click. [UIPI policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop), [`SendInput`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput).

A plan ID on a command line is **not a secret against the same user**: malware can request its own plan and launch the helper for that ID, causing a UAC prompt. It cannot supply the text the helper displays if the helper calls the service’s elevated `get_plan` and shows only the returned, service-built description. The service must include the action kind, target identity, scope, requester/session, expiry, and any irreversible effect in fixed Vietnamese wording; treat URL, host, filename, and path as quoted data, not instructions. Before approval, re-fetch or version-check the plan, revalidate the target, and consume it once. Timeout/cancel leaves no action. The current plan has a 120-second TTL and one-use pop (`agent/sentinel/service/core.py:27-29,195-209,223-240`), but `_plan_for` currently checks session **only**, not requester SID (`:213-225`), and `get_plan` does not reserve a single helper. Add a service-held claim per plan with expiry and helper token identity, reject a second concurrent helper, and specify the over-the-shoulder-admin case explicitly: an admin SID may differ from the requester SID, so display both identities and allow it only under an owner-approved policy.

**Unelevated test:** fake the service’s `get_plan`/approval responses, reject caller-supplied display text, and test expiry, cancellation, duplicate helper claims, and changed target/version. **Owner-only check:** exercise real `runas` approval and cancellation on a harmless test-only plan; verify the actual prompt identity and high-integrity token.

## 5. `tools/admin_acceptance.ps1` outline

The script should require a **high-integrity elevated Administrators token**, not merely membership in Administrators; fail before mutation if not. Use `GetTokenInformation(TokenElevation, TokenIntegrityLevel)` through a small P/Invoke helper and verify the interactive session. Require a disposable install/state root or disposable VM, unique service/pipe names supported by the test fixture, and a harmless marker rule. If the implementation cannot isolate service name, pipe, and state, **do not run lifecycle/uninstall tests against production**; mark that gate blocked until the disposable fixture exists. Do not change Defender settings. `Get-Acl` exposes owner and SDDL for filesystem and registry objects. [PowerShell `Get-Acl`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl).

For the medium-integrity checks, the elevated script should find the interactive shell with `GetShellWindow`, obtain its PID/token, verify the same target session, expected user SID, **medium** integrity and non-elevation, duplicate to a primary token, and launch a protected test client with `CreateProcessWithTokenW(LOGON_WITH_PROFILE, ...)`. Capture its structured JSON result through a disposable, ACL-scoped output or pipe; verify its token **inside the child**, too. If there is no suitable shell token, report `SKIP medium_client` and fail the gate rather than using the elevated process as a substitute. [`CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw).

| Order / output | Elevated evidence | Medium-client or other negative evidence |
|---|---|---|
| **1 `PASS preflight`** | Token check; protected roots; runtime files and hashes; exact `sys.path`; disposable fixture; no reparse points. | A separate unelevated import/path probe cannot import from checkout. |
| **2 `PASS service_config`, `RUNNING`** | Install/start; `sc.exe qc`, `qsidtype`, `qprivs`, `qfailure`, `qfailureflag`, `sdshow`; `QueryServiceConfig2W`; verify account `LocalSystem`, `AUTO_START`, SID type, privileges, recovery, and DACL. | Medium token can query; opening for `SERVICE_STOP`/change-config returns access denied. |
| **3 `PASS storage_pipe`** | `Get-Acl` owner/SDDL on root and each sensitive child; pipe security descriptor and local-only option. | Status and own-file scan accepted; direct DB/quarantine open/write denied; malformed/oversized and mutation requests rejected. Actual remote rejection requires a remote test peer; otherwise report `SKIP remote_os`, not `PASS`. |
| **4 `PASS worker`** | Inspect worker `TokenRestrictedSids`, low integrity, inherited handles, Job Object membership/limits; protected imports including YARA-X. | Harmless marker scan works; installed-code/store writes denied; intended handle readable; injected crash/OOM/timeout yields typed non-clean result and worker tree exits. |
| **5 `PASS usn_sources`** | Disposable NTFS volume cursor and restart; invalid cursor; harmless cross-user source. | Denial/reconciliation is explicit; no silent clean result. |
| **6 `PASS observation_download`** | Benign process churn and completed harmless file; read counters and interval gaps. | URL/path hint alone produces no privileged action. |
| **7 `PASS action_recovery`** | Test-only marker; stop during prepared action; inspect journal after restart. | No action after barrier, no double quarantine, identity rechecked. |
| **8 `PASS lifecycle`** | Read Defender mode only; crash recovery; clean stop; lease handoff; uninstall disposable service; verify installed code removal and retained state report. | Tray/native host report disconnection; no duplicate actor. |

Each step records observed values and fails on an unmet assertion; print `PASS` only after evidence exists. Use `try/finally` to stop/delete **only** the uniquely named disposable service, close handles, and remove only manifest-listed disposable code paths after verifying they remain under the intended root. Retain disposable quarantine/DB/journal when testing the default uninstall behavior, and report their locations for the owner to dispose of separately. R13b’s eight targets are at `docs/research/R13b-design-discussion.md:89-98`.

## 6. Migration and uninstall

The action lease belongs in `%ProgramData%\SentinelGuard\handoff\` or the protected service DB. **Only the service writes it**. The legacy tray receives a short, session/user-bound lease through IPC and renews it; it must check the lease immediately before each automatic action. The service starts observe-only, initializes DB/USN/workers, and waits for the old watcher’s stop barrier. The old tray relinquishes the lease; the service durably advances an epoch, enables actions, then reconciles from its cursor. A crashed tray cannot renew: after lease expiry and recovery of any prepared action, the service may take the lease. A restarted old tray must fail closed when it sees a newer epoch. This is an implementation inference for R13b P9’s agreed handoff (`docs/research/R13b-design-discussion.md:100-106`).

A same-user process can impersonate the tray at the pipe boundary (`agent/sentinel/service/authz.py:1-8`), so a lease is **coordination**, not malware-resistant authentication. Do not let an arbitrary user request create or prolong the migration lease indefinitely: initialize it only during the owner-authorized migration, cap its lifetime, bind it to the expected SID/session and transition epoch, and refuse new legacy leases after handoff. If the old tray can still act without a valid lease, the no-duplicate-action claim is unproven.

Handoff order: keep the existing HKCU native-host registration and HKCU Run entry while the legacy tray acts; switch the manifest’s absolute host path to a protected, IPC-only native host; start the new unelevated tray client; verify reconnection; remove the **correct user’s** HKCU Run entry after service activation. An elevated helper using another administrator account must address the original user’s hive by SID rather than assuming its own HKCU. Current registration and uninstall are per-user (`agent/sentinel/install.py:53-100`).

Uninstall order: block new actions, close the stop barrier, stop service and workers, remove SCM entry, remove per-user host/Run registrations for each enrolled user, then remove installed code after no process uses it. Keep quarantine, DB, feeds/policy history, and repair journal by default; report them and offer a separate explicit owner-directed purge. Never auto-restore quarantined bytes. This follows the recorded P9 decision (`docs/research/R13b-design-discussion.md:104-106`). If Defender or another AV removed a file, record external removal and revalidate identity; do not recreate or re-quarantine a replacement at the same path.

## Owner decisions and limits

- **Source trust:** approve how the pre-existing user-writable Python, YARA-X, and checkout snapshot are authenticated before elevated copying. Protected destination ACLs alone cannot answer this.
- **Consent identity:** decide whether an administrator with a different SID may approve a plan initiated by a standard user in the same session, with both identities displayed.
- **Acceptance environment:** provide a disposable VM or authorize parameterized disposable service/pipe/state names for the full lifecycle test.
- **UI branding:** direct protected Python is functional but prompts as Python; a Sentinel-branded launcher needs a build/signing decision.
- **Worker scratch/network:** use no scratch initially; if required, create a separately ACL’d low-integrity scratch directory. The current restricted token and Job Object do not enforce a network ban (`docs/research/R13b-design-discussion.md:63-71,127-133`).

No files were created, modified, or deleted, and no elevated command or acceptance test was run. The only local command beyond reading files was the `python -I -B` import/path inspection reported above.