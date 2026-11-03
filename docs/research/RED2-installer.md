# RED2: Installer, protected runtime and state ACLs

No elevated operations, service calls, network access, or pytest runs were made. The tests use temporary paths and the automatic `SENTINEL_HOME` fixture. The script findings are structural because running the batch file would elevate and touch the installed service.

## Critical — elevated execution from a user-writable checkout

**Attacker:** A medium-integrity process under the administrator's interactive account.

**Steps:** Replace `.venv\Scripts\python.exe` (or code it imports) in the user's checkout before the owner starts `tools/install_service.cmd`. The batch file elevates itself with `Start-Process -Verb RunAs`, changes to the checkout, and runs that relative interpreter for snapshot, uninstall, install, and verify. The attacker's code runs with the approved high-integrity token before protected staging begins.

**Effect:** Administrator execution of attacker-controlled bytes; those bytes can change service registration or protected files.

**Lines:** `tools/install_service.cmd:6-9,14,31,34,36,39,47`; `agent/sentinel/service/installer.py:389-412` also reads the mutable Python installation and checkout package into the snapshot.

**Fix:** Run an installer from an administrator-protected location with authenticated executable and package bytes. Bind the source digest the owner approved to the exact bytes staged; do not elevate a script that immediately executes the checkout interpreter.

**Test:** `test_red2_elevated_script_does_not_execute_checkout_python`. The unsafe command path is proven by the test and code; actual elevation is inferred and deliberately not exercised.

## High — reviewed snapshot is not bound to installed bytes

**Attacker:** A medium-integrity process able to write the owner's `%TEMP%` snapshot.

**Steps:** Let the owner create and inspect the snapshot, then alter `app/sentinel/__init__.py` before or after `plan_runtime` enumerates it. `install` accepts only a source path, not the printed snapshot digest. `write_runtime` reopens each source by path, hashes the newly copied bytes, and writes a manifest for those same bytes. Both integrity checks pass for the substituted content.

**Effect:** Attacker-controlled code enters the protected runtime and is later imported by the LocalSystem service.

**Lines:** `tools/install_service.cmd:15,31,36`; `agent/sentinel/__main__.py:289-294`; `agent/sentinel/service/installer.py:155-180,183-212,289-316,389-423`; `agent/sentinel/service/entry.py:12-14,56-69`.

**Fix:** Require the reviewed digest as an install input and verify it against the same bytes copied to protected staging. Hold or otherwise pin source file identities during the copy and reject source changes; sign or authenticate the source if the attacker can replace it before the review.

**Test:** `test_red2_snapshot_change_after_plan_is_rejected`. The plan-to-copy substitution is proven in process; the opportunity between human review and install is inferred from the script's `%TEMP%` path.

## Medium — protected service log copied into predictable user TEMP

**Attacker:** A medium-integrity process under the same split-token account, with access to that account's `%TEMP%`.

**Steps:** After the administrator runs the script, read or watch `%TEMP%\sentinel-install.log`. The elevated batch redirects all `:steps` output there and prints the tail of the administrator-only service log inside those steps. Service failures can include exception paths and other service context.

**Effect:** Information from the protected state tree is disclosed through a user-writable, predictable log file. The same path can also be modified to mislead the owner's printed result.

**Lines:** `tools/install_service.cmd:15-23,43-45`; `agent/sentinel/service/entry.py:63-72`; `agent/sentinel/service/backend.py:517,739`.

**Fix:** Write the elevated install log to an administrator-owned, access-controlled directory with a unique filename. Redact protected service details before deliberately publishing any result to the ordinary user.

**Test:** `test_red2_service_log_is_not_copied_to_user_temp`. The redirection and copy are proven structurally; cross-integrity readability follows from the shared user TEMP ACL and is inferred here.

FIX3: Dropped this test by design because the install script intentionally copies the service log to the owner's own `%TEMP%` while an administrator is present so the owner can read it.

## Other probes

The current code quotes the service binary path (`installer.py:282-286`) and validates the version component (`paths.py:17,66-72`). It refuses occupied code roots and version paths (`installer.py:302-304`), including preplanted directories and junctions. It creates code and state directories with explicit protected descriptors (`648-667`), requires SYSTEM ownership when reusing state (`775-806`), rejects reparse points while traversing state (`793-806`), and retains the protected state tree on uninstall (`353-362`). It generates `python315._pth` in protected staging (`183-208`) and limits snapshot root DLL names (`155-180`); the elevated checkout interpreter remains the DLL-loading concern in the critical finding. These checks did not yield a separate concrete finding in this round. The snapshot root's predictability and writable lifetime are covered by the high finding above.
