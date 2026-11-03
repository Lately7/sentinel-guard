# Codex red team round RED7: Approvals, the UAC helper and the tray

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red7_consent.py` and `docs/research/RED7-consent.md`. Everything else is read-only.

## Scope

`agent/sentinel/service/consent.py`, `service/core.py` approvals, `agent/sentinel/tray.py`, `overview_ui.py`, and anything they call that matters to the attack.

## Probe at least

Whether a medium-integrity process can get an approval it should not: argv injection into the elevated helper, a plan swapped between prompt and approval, approval reuse, prompts that show attacker-controlled text (right-to-left override and other bidi characters in file names, very long names, newlines), and UI states that tell the user they are protected when they are not.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
