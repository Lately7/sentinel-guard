# Codex fix round FIX3: install integrity (RED2)

Worktree: the RED2 worktree; the tests are `tests/codex/test_red2_installer.py`, the report
`docs/research/RED2-installer.md`.

## Allowed paths

`agent/sentinel/service/installer.py`, `tests/codex/test_red2_installer.py`, `docs/research/RED2-installer.md`.

## Findings

* `test_red2_snapshot_change_after_plan_is_rejected` (product bug, medium): the runtime is planned from the
  snapshot, then copied, and nothing checks that the copied bytes are the planned ones. Record each file's
  SHA-256 in the plan; after each copy, hash the copy and raise `InstallError("INSTALL_INTEGRITY", rel)` on a
  mismatch, so install's existing cleanup removes the tree.
* `test_red2_elevated_script_does_not_execute_checkout_python` (hardening, medium) is **deferred**: fixing it
  changes the owner's install flow, so it is owner question 15 in `docs/handoff/PLAN.md` §6. Mark it xfail strict
  with that reason.
* `test_red2_service_log_is_not_copied_to_user_temp` is **by design**: the install script copies the service log
  to the owner's own `%TEMP%` while an administrator is present, on purpose, so the owner can read it. Delete the
  test and note it in the report.
