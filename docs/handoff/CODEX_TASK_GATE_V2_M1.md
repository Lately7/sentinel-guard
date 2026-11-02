# Codex task — Gate v2 milestone 1: schema and pure policy

You are the implementer of Gate v2 for Sentinel Guard, the repository owner's
own Windows 11 anti-malware prototype. Claude (the primary developer) wrote
this task, will review every line you write, run the tests and decide whether
to merge. The owner decided on 2026-11-02 that you write Gate v2 from your own
specification `docs/research/R11-gate-v2-knowledge-pack.md` (R11).

## Pinned start

* Working directory: the git worktree `..\sentinel-guard-gate-v2`, branch
  `codex/gate-v2-m1`.
* Start commit: **682a495** (`git log -1 --format=%h` must print `682a495`
  before you write anything; if it does not, stop and report).
* This task file is given to you as the prompt; it is not in your tree.

## Allowed paths (nothing else may change)

* `agent/sentinel/gate_v2/` (new package)
* `tests/gate_v2/` (new test folder)

Do not change, create, rename or delete anything else: no existing production
code, no existing tests, no `pyproject.toml`, no docs, no `.gitignore`.
`agent/sentinel/engine/` and every existing caller stay untouched in this
milestone. Do not commit; leave your work as untracked/modified files —
Claude commits after review. Claude runs
`tools/check_codex_scope.ps1 -Base 682a495 -Allow "agent/sentinel/gate_v2/,tests/gate_v2/"`
after you finish; any file outside these paths rejects the whole round.

## What to build (R11 §8 row 1)

Read first: R11 §§2, 4, 6 and 7 (rows "Contract/validation" and "Verdict
table"); `docs/handoff/PROJECT_CONTEXT.md` §§7 and 11 (locked owner
decisions; do not re-argue them); `AGENTS.md`.

1. `agent/sentinel/gate_v2/__init__.py` — package marker; may re-export the
   public names.
2. `agent/sentinel/gate_v2/contract.py` — the R11 §4 types with exactly the
   field names, enum values and version constants shown there
   (`CONTRACT_VERSION = 2`, `EVENT_VERSION = 1`, policy version strings
   `"evidence-v1"` and `"legacy-v0"`). Frozen dataclasses, `StrEnum`s.
   Add:
   * validation per R11 §4 "Validation rules" (negative sizes/durations,
     unsorted/overlapping/out-of-bounds ranges, duplicate engine IDs, missing
     identity for a completed path scan, `COMPLETED` with an error, `CLEAN`
     from a non-`COMPLETED` stage, conclusive evidence with
     `verified=False`, unknown contract/event version, malformed SHA-256,
     `ScanRequest` with both or neither of `path`/`data`). Raise one
     dedicated exception type (e.g. `ContractError`) with a stable code.
   * `to_dict()` / `from_dict()` (or module functions) producing plain
     JSON-compatible data; `from_dict` validates and rejects unknown
     versions and unknown enum values. Round trip must be exact.
   * bounds: every free-text field (`raw_name`, `member_path`, `message`,
     reason lists) has a documented maximum length/count; over-long input is
     rejected or truncated deterministically — say which in a docstring.
   * `ScanEvent` must not be able to carry a path, hash, URL or raw engine
     output (R11 invariant 14): its fields are the R11 §4 ones only.
3. `agent/sentinel/gate_v2/coverage.py` — byte-range normalisation and union,
   containment checks, a small coverage ledger for container children
   (seen / inspected / opaque / omitted, each omitted/opaque child with a
   stable reason code; bounded number of stored reasons with an overflow
   counter), and construction of a `Coverage` value with the right `mode`
   (`full`, `fixed_partial`, `runtime_partial`, `none`). Limits hit are
   recorded explicitly (invariant 8).
4. `agent/sentinel/gate_v2/policy.py` — pure, deterministic:
   * ClamAV name classification per R11 §6 "Evidence classification":
     coverage names (`Heuristics.Limits.Exceeded.*`, `Heuristics.Encrypted.*`)
     → coverage, not malware; weak prefixes (`PUA.`, `Heuristics.`,
     `BC.Heuristics.`, `Weak.`) and a reviewed weak-name set containing
     `Win.Trojan.Suspect-34` → supporting; first match wins, so
     `PUA.Win.Exploit.*` stays weak; `Generic`/`Gen`/`Agent` are not weak;
     everything else → conclusive (locked default, PROJECT_CONTEXT §7.5–7.6,
     §11 R6).
   * `decide(results, request, gate_generation) -> FinalDecision` implementing
     the R11 §6 "Final decision table" top to bottom with reason codes.
     "Required applicable stage" must be an explicit input (for example a
     policy object listing required engine IDs and which are disabled by
     policy), not guessed from engine names.
   * `should_auto_quarantine(decision, *, policy_version, auto_quarantine,
     protection_generation, ...) -> ActionDecision` implementing the R11 §6
     action table. Extra keyword inputs you need (current protection
     generation, whether the current file identity was re-verified, restore
     exception / trust match) are explicit parameters.
   * Two action policies:
     - `evidence-v1`: exactly the R11 action table.
     - `legacy-v0` (the **locked default** until the owner switches): keeps
       today's user-visible auto-quarantine of ClamAV names — today
       `agent/sentinel/engine/clamav.py:228-233` downgrades only
       `Heuristics.` and `PUA.`, so e.g. `Win.Trojan.Suspect-34` is still
       auto-quarantined under legacy-v0 (that is open issue RT-001; keep it
       reproducible, with reason code e.g. `LEGACY_V0_CLAMAV_NAME`).
       Everything else is evidence-v1: legacy-v0 must still refuse action on
       unverified evidence, changed identity, revoked protection generation,
       and must never produce `trusted_clean`. It does not reproduce the old
       score arithmetic (that belongs to the legacy adapter, milestone 6).
   * No I/O, no clock reads, no randomness, no imports from
     `sentinel.engine`, `sentinel.db` or any other existing Sentinel module.
     Stdlib only.
5. `tests/gate_v2/` — pytest tests (the root `tests/conftest.py` already sets
   a temporary `SENTINEL_HOME`; you need no I/O at all). Required:
   * every invariant of R11 §2 that milestone 1 can express gets at least one
     named test referring to its number (1, 3, 4, 5, 6, 7, 8 in pure form,
     12 for the cacheable flag, 13 for restore/trust reason codes, 14);
     list the ones that need later milestones in the module docstring;
   * the R11 §7 "Verdict table" cartesian matrix: every `StageStatus` ×
     {no hit, weak, PUA, conclusive, coverage-name} × {required, not
     required}, with the expected verdict / `trusted_clean` / reason code;
     conflicting engines; EICAR flagged `is_test_file` still malicious;
   * contract round trip for every enum value and every dataclass;
     rejection of each validation rule above;
   * action table for both policies, including RT-001 behaviour differing
     between `legacy-v0` and `evidence-v1`.

## Constraints

* Python 3.12+, fully type-annotated, stdlib only. Small modules; comments
  explain why, not what. English identifiers and comments.
* Files must use LF line endings (write bytes or set `newline="\n"`).
* Positive samples: none needed. Never write EICAR or any malware to disk;
  no network.
* Do not weaken R11: if a rule there is ambiguous, pick the stricter reading
  (no false clean, no action) and list the ambiguity in your answer.

## Running the tests

From the worktree root:
`..\sentinel-guard\.venv\Scripts\python -m pytest -q tests/gate_v2`
(the venv lives in the main checkout; `pyproject.toml` puts this worktree's
`agent/` first on `sys.path`). If the sandbox prevents running it, say so;
never report a test as passed unless you ran it and saw the output.

## Your answer

English, concise: files created (with line counts), public API summary,
the invariant → test mapping, the exact pytest command and its real output
line, ambiguities you resolved and how, and anything you would change in R11.
