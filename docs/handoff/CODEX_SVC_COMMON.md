# Codex rounds SVC1–SVC3: common rules

The Windows service in `agent/sentinel/service/` is installed and running on this machine, for the
first time. A review of the running product found the faults listed in your task. You fix them.
Claude reviews every line, runs the tests and merges. Stay on the branch this worktree is on; do not
commit.

**A finding is a claim, not a fact.** Read the code first. If a finding does not hold, or its fix
would break something the code clearly relies on, skip it and say why. A skipped finding with a good
reason is a good result. Do not widen a fix beyond what it needs.

**Every fix needs a test that fails before the fix and passes after it.** Put new tests in the one
test file your task names; do not edit other test files. Say which test covers which finding.

**Sandbox note:** you cannot run pytest in this sandbox (temp folder denied). That is not a reason to
stop: implement everything, re-read your code against each test, say which test covers what. Never
create temp or probe folders. Claude runs the suites.

## Hard rules

* Files outside your task's allowed paths are read-only. `tools/check_codex_scope.ps1` enforces this.
* Never elevate, never touch the installed service, `C:\Program Files\SentinelGuard` or
  `C:\ProgramData\SentinelGuard`. Never change system or Defender settings. No network, no downloads.
* Tests use harmless inputs only: the marker rule in `tests/conftest.py`, EICAR in memory. Never write
  EICAR to disk. No malware, no evasion.
* Tests never reach the installed service: `tests/conftest.py` already blocks the real pipe name.
* Python 3.15, type-annotated, stdlib only in the service. No new dependency. Argv arrays, `shell=False`.
* Never call `repr()` or `str()` on objects of unknown type in inspection code.
* Code, identifiers and comments in English; comments explain why, not what, and match the density of
  the code around them. User-facing text is Vietnamese. Files use LF.
* A clean verdict is never reported for something not checked. Nothing here may turn an unknown into a
  clean, and nothing may make an action run on bytes other than the ones measured.

## Your final answer

Per finding: done or skipped and why, files touched, the test that covers it, anything you are unsure
of. Keep it under 400 words.
