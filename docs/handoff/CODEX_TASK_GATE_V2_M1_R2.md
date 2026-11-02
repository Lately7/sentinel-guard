# Codex task — Gate v2 milestone 1, round 2: review fixes

Same rules as `CODEX_TASK_GATE_V2_M1.md` (round 1). Working directory: the
worktree `..\sentinel-guard-gate-v2`, branch `codex/gate-v2-m1`. HEAD must be
**72517f7** (your round-1 files, committed by Claude so this round has a clean
diff); if not, stop and report. Allowed paths unchanged:
`agent/sentinel/gate_v2/`, `tests/gate_v2/`. Do not commit.

Claude reviewed every line of round 1. Structure, validation and the test
matrix are good. Fix these findings; each needs a test that fails on 72517f7
and passes after your change.

## Must fix

**F1 — false clean from dropped detections (invariants 1 and 3).**
`policy.decide()` silently skips detection evidence that is not accepted
(unverified evidence, evidence from a stage whose status is in
`_BAD_STATUSES`, evidence outside the inspected ranges, identity mismatch).
When that stage is not in `RequiredStages.required`, the result is
`clean`/`trusted_clean=True`: e.g. an optional ClamAV stage with status
`UNVERIFIED` and a conclusive-looking `FOUND` name yields trusted clean
(`test_verdict_cartesian_matrix`, `required=False` branch, encodes this).
Required: any malware/PUA/riskware evidence of strength conclusive, strong or
supporting that is **not accepted**, for whatever reason and whether or not
the stage is required, makes the verdict at least `unknown` when nothing
else was accepted, with a stable reason code (e.g. `UNACCEPTED_DETECTION`)
appended after the stage reasons, `trusted_clean=False`, not cacheable.
Accepted detections keep their precedence (malicious > suspicious > unknown).
Update the matrix expectations accordingly. The action for an unverified
ClamAV lead stays `NOTIFY`/`UNVERIFIED_CLAMD`.

**F2 — conclusive non-malware evidence is dropped.** Evidence with
`strength=CONCLUSIVE` and a category other than `MALWARE` (PUA, riskware,
structure, origin, health) is neither counted as conclusive nor as weak, so it
vanishes and the file can be clean. Conclusive-strength evidence of category
PUA or riskware must count as a weak/PUA detection (`suspicious`, reason
`PUA_DETECTION` for PUA); structure/origin/health evidence stays context and
does not change the verdict (say so in a comment).

**F3 — on-demand scans can never act.** `should_auto_quarantine()` returns
`PROTECTION_STOPPED` whenever `protection_generation is None`. In R11
`ScanRequest.protection_generation` is `None` for scans that are not tied to a
real-time protection run (CLI, on-demand, download). The stop barrier applies
only when the decision carries a generation: stopped iff
`protection_generation is not None and protection_generation !=
current_protection_generation`. Test both: `None` with a conclusive hit →
`QUARANTINE`/`AUTO_CONCLUSIVE`; generation 7 vs current 8 → `PROTECTION_STOPPED`;
generation 7 vs current `None` (protection switched off) → `PROTECTION_STOPPED`.

**F4 — `FinalDecision.duration_ms` is a timestamp.** It is computed as
`max(started_monotonic_ns + duration) // 1e6`, an absolute monotonic time. Use
`(max end − min start)` in milliseconds, `0` for no results; test it.

**F5 — `tests/gate_v2/conftest.py` must go.** It points `SENTINEL_HOME` at a
folder inside the repository, which breaks a hard repository rule (tests use a
temporary `SENTINEL_HOME` only). Delete the file; the root `tests/conftest.py`
fixture (tmp_path) applies. To run pytest inside your sandbox, pass a base
temp folder inside the worktree, e.g.
`..\sentinel-guard\.venv\Scripts\python -m pytest -q tests/gate_v2 --basetemp .codex-pytest-tmp -p no:cacheprovider`,
then delete `.codex-pytest-tmp` and any `__pycache__` you created. If it
still cannot run, say so; Claude runs the suite outside the sandbox.

**F6 — unknown parser states count as complete.** `CoverageLedger.parser()`
marks enumeration incomplete only for four listed state strings; any other
string (`"timeout"`, `"failed"`, a typo) silently counts as complete. Use an
allow-list: only `"complete"` is complete, everything else marks the
enumeration incomplete. Test with an unlisted state.

## Small

* F7: replace `__import__("typing").Union` in `contract.py` with a normal
  `from typing import Union` import.
* F8 (no code change): `decide()` turns `certainty="declared"` on a completed
  stage into `UNCERTAIN_COVERAGE`, so a ClamAV `OK` can never contribute to
  trusted clean. R11 §6 allows a verified-daemon `OK` on a simple file to
  satisfy its outer-byte stage. Keep the strict rule for milestone 1, but add a
  short comment at that line naming it as an open point for milestone 4.

## Your answer

English, concise: per finding, what changed (file:line) and the test name;
the exact pytest command and its real output line; anything you disagree with.
