# Codex red team round RED2: Installer, protected runtime and state ACLs

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red2_installer.py` and `docs/research/RED2-installer.md`. Everything else is read-only.

## Scope

`agent/sentinel/service/installer.py`, `service/entry.py`, `service/host.py`, `tools/install_service.cmd`, and anything they call that matters to the attack.

## Probe at least

Whether an ordinary user can plant or replace anything the LocalSystem service loads or writes: the snapshot source, `._pth`, DLL search order next to `python.exe`, the state tree under ProgramData and its inherited ACLs, junctions planted before install, a pre-existing directory owned by the user, `%TEMP%` paths used by the install script, the version directory name, uninstall leaving a writable tree, the service binary path quoting.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
