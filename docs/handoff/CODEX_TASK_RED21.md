# Codex red team round RED21: Scan engines and their untrusted output

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red21_engines.py` and `docs/research/RED21-engines.md`. Everything else is read-only.

## Scope

`agent/sentinel/engine/`, `gate_v2/defender.py`, the clamd adapter and the YARA and signature engines, and anything they call that matters to the attack.

## Probe at least

Output a malicious file can cause an engine to print: names with newlines, quotes, very long lines, mixed encodings, a fake `Threat :` line inside a file name, exit codes outside the documented set, an engine that hangs or floods stdout, and every place parsed engine output decides a verdict or reaches the UI.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
