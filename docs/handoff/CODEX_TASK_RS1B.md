# Codex task RS1B: finish RS1 on the service path

You are continuing RS1 in the same worktree; its uncommitted changes are yours to keep (`service/backend.py`,
`tray.py`, `__main__.py`, `tests/test_rs1.py`). The RS1 brief named `agent/sentinel/bridge.py`; the live file is
`agent/sentinel/service/bridge.py`, and `agent/sentinel/service/consent.py` discards the service's action reply.

## Allowed paths

Changed: `agent/sentinel/service/bridge.py`, `agent/sentinel/service/consent.py`, plus the four RS1 files above.
Everything else is read-only.

## Build

Carry `zone_identifier_preserved` from the service's restore reply through `consent.py` and `service/bridge.py`
to the tray and the CLI, so a restore approved through the service shows the same Vietnamese warning as a local
restore when the value is false. A reply without the field (an older service) reads as null and shows nothing.
Do not change what any other action returns or how approvals work. Add the tests to `tests/test_rs1.py`: the
value reaches the tray and CLI for false, nothing for true and null, and a reply without the field.
