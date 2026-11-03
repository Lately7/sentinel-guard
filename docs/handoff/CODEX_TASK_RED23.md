# Codex red team round RED23: Tray and overview UI

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red23_ui.py` and `docs/research/RED23-ui.md`. Everything else is read-only.

## Scope

`agent/sentinel/tray.py`, `overview_ui.py` and any notification path, and anything they call that matters to the attack.

## Probe at least

Text from files, URLs, engines or events shown without neutralizing bidi and control characters, UI threads blocked by service calls, a hostile medium process that floods events to bury a real alert, states where the UI shows protected while the service or worker is down, and actions a user can trigger that do something other than what the button says.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
