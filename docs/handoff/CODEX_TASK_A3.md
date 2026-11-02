# Codex task — A3: protected install, service registration, consent helper, acceptance script

You implement A3. Claude reviews every line, runs the tests and merges. Stay on the
branch this worktree is on; do not commit.

**Sandbox note:** you cannot run pytest in this sandbox (temp folder denied). That is *not*
a reason to stop: implement everything, re-read your code against each test, and say which
test covers what. Never create temp or probe folders. Claude runs the suites.

## Read first

`docs/research/R16-service-install-acl.md` (the design; follow it, list every deviation),
`docs/research/R13b-design-discussion.md` (P1, P2, P3, P5, P7, P8, P9), `REVIEWS.md` (R15-2,
R15-4), `agent/sentinel/service/` (all), `agent/sentinel/config.py`, `agent/sentinel/install.py`.

## Allowed paths

New: `agent/sentinel/service/paths.py`, `installer.py`, `integrity.py`, `consent.py`,
`entry.py`, `tools/admin_acceptance.ps1`, `tests/test_service_installer.py`,
`tests/test_service_consent.py`. Changed: `agent/sentinel/service/client.py`, `winpipe.py`,
`worker.py`, `workerclient.py` (only where listed below), `tests/test_service_winpipe.py`.
Everything else is read-only; `__main__.py` belongs to Claude: expose functions, Claude adds
the `sentinel service ...` commands. No new dependency. Argv arrays, `shell=False`.

## Build

1. `paths.py`: installed-mode paths from `SHGetKnownFolderPath` (never `%ProgramFiles%` or
   `%ProgramData%` from the environment), version directory, state tree of R16 §3. Installed
   mode ignores `SENTINEL_HOME`. Tests inject a root.
2. `installer.py`: pure, testable parts first. `plan_runtime(source)` lists what to copy
   (R16 §1: exclude `pyvenv.cfg`, `pip`, `.pth`, `.egg-link`, `sitecustomize`, `__pycache__`,
   `.pyc`, dev tools); `write_runtime(plan, target)` copies as new files, writes
   `python315._pth` named for the running interpreter's DLL, and records SHA-256 of every file
   in a manifest; `install()` and `uninstall()` do the SCM sequence of R16 §2 through `ctypes`
   behind an injected `Scm` interface, so tests assert every argument, structure size, SDDL
   string and cleanup path. `install()` must refuse to run unelevated with a typed error, and
   must stage everything before registering. Registering the current checkout is impossible by
   construction: the binary path must be inside the protected version directory. `--dry-run`
   prints the plan and needs no rights.
3. State tree creation per R16 §3 **including the pre-creation procedure**: inspect without
   following reparse points; an existing object not created by us → `INSTALL_PATH_OCCUPIED`,
   never "fix" it in place. Pure classification is unit-tested with a fake filesystem and with
   a real junction under a temp root.
4. `integrity.py`: the start-up self-check of R16 §1 and §3 (`INSTALL_INTEGRITY`,
   `STATE_ACL_UNSAFE`): exact `sys.path`, `sys.flags.isolated`, `sys.dont_write_bytecode`,
   protected locations of loaded modules, `SetDefaultDllDirectories`. Fail closed.
5. `entry.py`: installed entry point: run the integrity check, then `host.run_as_service` with a
   `ServiceCore` backend passed in by a factory (Claude supplies the real backend in M7).
6. `consent.py`: small native dialog through `ctypes` (`MessageBoxW` with no default on "Có"),
   not Tk. Takes a validated hex plan id, connects to the service, fetches the plan with
   `get_plan`, shows only the service's text with a fixed Vietnamese title, approves with
   `approve_plan`. Plus `launch_consent(plan_id)` for the tray: `ShellExecuteExW` verb `runas`,
   absolute protected path, bounded wait, `ERROR_CANCELLED` is a normal denial. Add a service-held
   claim per plan so a second helper is refused (`service/core.py` is yours for this one change;
   list it).
7. **R15-2:** `client.py` must verify who answers: after connecting, `GetNamedPipeServerProcessId`
   → open the process → its token user must be the expected SID (default LocalSystem; tests pass
   the current user's SID). A wrong server raises a typed error and the client disconnects without
   sending anything. Test with a squatting same-user fake pipe.
8. `worker.py`: installed mode launches the protected executable with `-I -B -m
   sentinel.service.workermain` and adds the service SID to `SidsToRestrict`; development mode keeps
   today's bootstrap. `SystemRoot` comes from the OS, not the parent environment.
9. `tools/admin_acceptance.ps1`: the eight ordered checks of R16 §5, with its fixture rules. It
   refuses to run unelevated, prints `PASS <name>` only after evidence, never touches Defender
   settings, and works on a uniquely named disposable service, pipe and state root. A `-WhatIf`-style
   dry mode needs no rights.

## Rules

Comments explain why. User-facing text is Vietnamese. Harmless synthetic data only. No test needs
elevation; say which checks only the owner's script can prove.

## Your answer

English, concise: files and line counts, per item the test that covers it, deviations from R16,
everything Claude must wire, everything only the owner can verify.
