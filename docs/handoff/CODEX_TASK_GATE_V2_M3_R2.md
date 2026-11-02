# Codex task — Gate v2 milestone 3, round 2: review fixes

Same rules as `CODEX_TASK_GATE_V2_M3.md`. Worktree `..\sentinel-guard-gate-v2`,
branch `codex/gate-v2-m3`; HEAD must be **57b8aa1** (your round-1 files,
committed by Claude), else stop and report. Allowed paths:
`agent/sentinel/gate_v2/`, `tests/gate_v2/`. Do not commit.

Claude ran `tests/gate_v2` outside the sandbox: **2 failed, 160 passed,
1 warning**. Claude read every line. The bound reader, the JSON pack schema
and the ZIP reason codes are good. Fix the findings below; each needs a test
that fails on 57b8aa1 and passes after.

## Must fix

**H1 — archive members are "inspected" without being checked (false clean).**
`core._inventory` marks a member `inspected` after merely decompressing it:
no hash, no name check, no PE/script signals. The JSON-rule and YARA-X
adapters see only the outer (compressed) bytes. So a ZIP whose member is the
EICAR test file — or the marker file — ends `clean` and `trusted_clean`. The
old scanner checked member contents (`engine/scanner.py:236-306`); this is a
regression. Required:
* one shared, bounded archive walker (e.g. `gate_v2/archive.py`) that yields
  member bytes under the existing limits and records the ledger reasons;
* core checks every member: SHA-256 against EICAR and the injected known-bad
  lookup (conclusive, `scope="member"`, bounded `member_path`), name checks
  (double extension, RTLO, padded names), PE/script signals;
* the JSON-rule and YARA-X adapters scan member bytes too, with
  `scope="member"`;
* a member counts as `inspected` for an engine only if that engine examined
  its bytes; otherwise it is coverage debt for that engine.
Tests: EICAR inside a ZIP built **in memory** (bytes request, never on disk)
→ `malicious`; the marker inside a ZIP on disk → JSON user rule conclusive →
`malicious`; a nested ZIP at depth 2 with the marker → found; depth beyond the
limit → omitted, verdict never `clean`/trusted.

**H2 — content can change under the bound reader.** `BoundReader._check`
compares metadata only, and `ChangeTime` is settable through
`SetFileInformationByHandle`, so a same-size rewrite with restored times can
pass. Hold the measured handle **deny-write**: open with `CreateFileW`
(`GENERIC_READ`, share `FILE_SHARE_READ | FILE_SHARE_DELETE`) via `ctypes`
and `msvcrt.open_osfhandle`; keep the existing metadata check as a second
line. If a writer already holds the file, return a typed `IN_USE` result
(the watcher's locked-file retry, RT-016, handles it). Test on Windows: while
the reader is held, opening the file for writing fails; a file already open
for writing gives `IN_USE`. Skip with a reason elsewhere.

**H3 — duplicated measurement.** `BoundReader.measure_path` re-implements
`identity.measure`. Factor one measurement routine that works on an open
stream and use it from both, so the two cannot drift.

**H4 — YARA-X `Scanner` dropped on the wrong thread.** Claude's run shows
`RuntimeError: yara_x_py::Scanner is unsendable, but is being dropped on
another thread` (PytestUnraisableExceptionWarning): thread-local scanners
are garbage-collected from another thread. Create and drop the `Scanner`
inside the scan call (compiled `Rules` stay shared), or otherwise guarantee
same-thread release. Make the YARA tests fail on unraisable-exception
warnings (`pytestmark = pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning")`).

**H5 — YARA-X evidence provenance (R12a §6).** `raw_name` holds the tag
tuple; use `"<namespace>.<identifier>"`. Evidence `ranges` cover the whole
body instead of the match: use the matched pattern offsets/lengths (bounded
count) so coverage and evidence binding stay exact.

**H6 — the two failing tests and the missing ones.**
* `test_zip_member_states`: the ledger's own `MAX_CHILDREN` cap fires before
  your `MEMBER_LIMIT` reason; make code and test agree on one reason.
* `test_bound_reader_limits_and_change`: an oversized read raises
  `RESIDENT_LIMIT` before cancellation is checked; decide the order and test it.
* Add the tests the round-1 brief required and you said are missing: YARA-X
  timeout (tiny timeout + a deliberately slow synthetic rule) → `TIMEOUT`;
  match cap respected; a compile warning recorded in the manifest; a source
  with an error recorded as rejected; the same JSON rule in a bundled pack →
  supporting but in the user pack → conclusive; end to end on a clean
  synthetic file with all stages complete → `clean` with the
  `trusted_clean` value M1 policy gives (state which and why).

## Running the tests

`..\sentinel-guard\.venv\Scripts\python -m pytest -q tests/gate_v2 -p no:cacheprovider`
If the sandbox refuses temp folders, report it and stop there; create no temp
or probe folders. Claude runs everything outside the sandbox.

## Your answer

English, concise: per finding, the change (file:line) and test name; the
exact command and its real output; disagreements.
