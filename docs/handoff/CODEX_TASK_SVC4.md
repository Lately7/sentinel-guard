# Codex task SVC4: the log, and a test of the installed shape

## Allowed paths

Changed: `agent/sentinel/service/entry.py`. New: `tests/test_svc4.py`,
`tests/test_service_installed_shape.py`. Everything else is read-only.

## Findings

**1. `service.log` grows without bound.** `entry.py:62`, `logging.basicConfig(filename=...)`. A worker
that is down writes a line per attempt, for as long as the machine runs. Use a `RotatingFileHandler` of
about 5 MiB with 3 backups, UTF-8, same format and level. The rotated files sit in `journal`, so
`installer.verify_protected_tree` reads them at the next start: they must pass it, and they do if they
are made by the service inheriting the folder's ACL. Say so if you find otherwise. Test in
`tests/test_svc4.py`.

**2. No test runs the worker the way the installed service does.** The unit tests launch it with the
caller's identity and no restricting SIDs, which is why a worker that always died passed them all. Write
`tests/test_service_installed_shape.py`, Windows only, with a module-scoped fixture that:

* builds a runtime in a temp folder with `installer.snapshot_runtime`, `plan_runtime`, `write_runtime`;
* gives every entry the shape of `installer.CODE_SDDL` through `WindowsScm._secure_path`, using a made-up
  service SID, `S-1-5-80-1111111111-2222222222-3333333333-4000000000-1234567890`, and this SDDL with the
  caller's SID as `me`, since only an elevated token can name SYSTEM:
  `O:{me}G:{me}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})(A;OICI;FRFX;;;BU)(A;OICI;FRFX;;;{sid})`.
  Patch `installer.verify_path_acl` and `installer.enable_privilege` to no-ops for this, as
  `tests/test_service_installer.py` does.

Tests:

* `worker.launch(["-m", "sentinel.service.workermain"], python=<runtime>/python.exe, cwd=<runtime>,
  service_sid=<made-up>)` answers `init` with `core`, `json_rules`, `yara_x`, `lnk`, `signer`;
* the same worker scans a harmless file through a duplicated handle and returns `completed`, as
  `WorkerSession._duplicate` does it;
* a worker cannot read a file whose DACL names only the caller and SYSTEM, which is what the state tree
  and a user's profile look like to it, and cannot write beside a file it can read;
* a rule set over `protocol.MAX_FRAME` reaches it.

Use `worker._private_desktop()` as the code does. Do not reset its module state between tests: the
handles must stay open. The fixture must leave nothing behind that a later test depends on.
