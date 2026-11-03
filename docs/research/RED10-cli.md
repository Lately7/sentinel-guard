# RED10 — CLI, configuration, and environment

These tests use harmless placeholder files under `tmp_path`. They replace process-launch functions with capture functions, make no network request, and do not contact an installed service. The privilege impact below assumes an elevated CLI process inherits environment values controlled by the ordinary user. The tests prove executable selection, not that inheritance or actual code execution.

## High — Defender path follows `ProgramData`

- **Attacker model:** An ordinary user controls the environment and a directory they can write. An administrator runs an elevated `sentinel scan` with that environment.
- **Steps:** Set `ProgramData` to the writable directory, create `Microsoft/Windows Defender/Platform/1/MpCmdRun.exe` there, and scan a file for which Defender is selected.
- **Effect:** The scan launches the user's executable with the CLI process token. Its output can also be accepted as a Defender result.
- **Exact lines:** `agent/sentinel/__main__.py:29-41` constructs the scanner; `agent/sentinel/engine/defender.py:55-67` selects the first existing executable under environment-derived `ProgramData`; `agent/sentinel/engine/defender.py:107-120` invokes it. `agent/sentinel/engine/scanner.py:86-93,120-167` connects that selection to scan planning.
- **Proposed fix:** Resolve the actual Windows ProgramData known folder independently of the process environment, reject reparse points and untrusted ACLs on the selected binary and ancestors, and fail closed if no trusted Defender executable is found.
- **Evidence:** `test_defender_path_ignores_user_programdata` proves selection of the fake path today. Elevated code execution is inferred from the subprocess call under the stated precondition.

## High — ClamAV override selects a user executable for maintenance

- **Attacker model:** An ordinary user controls `SENTINEL_CLAMAV_DIR` and its directory. An administrator runs elevated `sentinel clamav update` with that environment.
- **Steps:** Put harmless stand-ins for `clamd.exe` and `freshclam.exe` in the directory, then set the override to it.
- **Effect:** The update launches `freshclam.exe` from the user directory with the CLI process token. The same selector feeds other ClamAV commands.
- **Exact lines:** `agent/sentinel/__main__.py:351-359` invokes update; `agent/sentinel/engine/clamav.py:48-60` accepts the override and tests only for `clamd.exe`; `agent/sentinel/engine/clamav.py:175-184` launches `freshclam.exe`. `agent/sentinel/engine/clamav.py:286-288` and `agent/sentinel/service/backend.py:760-769` show that `machine_only` is enabled for the service, not the CLI.
- **Proposed fix:** Do not honor the directory override in an elevated process. Resolve a trusted machine install location, verify the chosen executable and ancestors, and reject untrusted reparse or writable paths.
- **Evidence:** `test_clamav_update_ignores_user_binary_override` proves the fake executable enters subprocess arguments today. Elevated code execution is inferred under the stated precondition.

## High — service verification takes `sc.exe` from `SystemRoot`

- **Attacker model:** An ordinary user controls the environment and a directory they can write. An administrator runs elevated `sentinel service verify` with that environment.
- **Steps:** Set `SystemRoot` to the user directory and place `System32/sc.exe` there.
- **Effect:** Verification starts the user's executable as administrator. With `--restart`, the same path is also used for stop and start operations.
- **Exact lines:** `agent/sentinel/__main__.py:282-298` dispatches verification; `agent/sentinel/service/verify.py:49-51` builds and launches `sc.exe` from `SystemRoot`; `agent/sentinel/service/verify.py:237-250` gates on elevation and then calls `sc`; `agent/sentinel/service/verify.py:215-233` uses `sc` to restart when requested.
- **Proposed fix:** Locate the real System32 directory through a trusted Windows API rather than `SystemRoot`; reject reparse or user-writable executable paths before launch.
- **Evidence:** `test_service_verify_ignores_user_systemroot` proves the fake executable enters subprocess arguments today. Elevated code execution is inferred under the stated precondition.

## Boundary checked

`SENTINEL_HOME` directs portable and test state through `agent/sentinel/config.py:24-34`. The installed service overwrites it with its protected state root at `agent/sentinel/service/entry.py:56-63`; its installed code and state paths come from Windows known folders at `agent/sentinel/service/paths.py:25-47,66-72`. The user-editable settings file therefore did not yield a supported path to turn off installed service protection in this review.

Pytest was not run in this sandbox, as required by the round brief.
