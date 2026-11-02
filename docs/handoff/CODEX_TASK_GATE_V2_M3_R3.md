# Codex task — Gate v2 milestone 3, round 3: two defects and the missing tests

Same rules as `CODEX_TASK_GATE_V2_M3.md`. Worktree `..\sentinel-guard-gate-v2`,
branch `codex/gate-v2-m3`; HEAD must be **6f9618d** (your round-2 files,
committed by Claude), else stop and report. Allowed paths:
`agent/sentinel/gate_v2/`, `tests/gate_v2/`. Do not commit.

Round 2 fixed H1–H5 correctly; Claude's run: `tests/gate_v2` **167 passed**.
Reviewing the member scanning turned up two defects. Each fix needs a test
that fails on 6f9618d.

## Must fix

**H7 — a later conclusive hit is cut off (false negative).** Every adapter
returns `tuple(evidence[:64])`. With member scanning, a ZIP with 80 members
named `invoiceN.pdf.exe` followed by an EICAR member yields 64 weak
`DOUBLE_EXTENSION` items and **drops the EICAR evidence**: Claude reproduced
it in memory — `CoreAdapter` through `orchestrator.scan` → verdict
`suspicious`, `eicar kept: False`. Required: before any cap, order evidence
by strength (conclusive first, then strong, supporting, context) and keep
every conclusive item ahead of weaker ones; deduplicate repeated weak items
of the same code (count them instead); when anything is dropped, record a
limit (e.g. `EVIDENCE_CAP`) in coverage so the result cannot be trusted
clean. Same rule in `core.py` and `rules.py` (one shared helper). Test:
exactly Claude's case (EICAR built in memory from `tests/conftest.py`'s
`EICAR`, never written to disk) → `malicious`, and a JSON user rule hit
after 80 weak members → `malicious`.

**H8 — no overall time bound across archive members (invariant 8).** The
YARA-X timeout applies per `scan()` call, so a 2,000-member archive can run
for 2,000 × the timeout; JSON and core member loops have no time check
either. Use the request's `deadline_monotonic_ns` (and cancellation) inside
`archive.walk`: when it passes, stop walking, record the remaining members as
`omitted` with a stable reason (e.g. `DEADLINE`), and return
`TIMEOUT`/partial coverage — never clean. Test with an injected clock or a
deadline already in the past after the first member.

## Missing tests (asked for in rounds 1 and 2)

* YARA-X **timeout**: a deliberately slow synthetic rule (for example many
  `for any i in (0..filesize)` loops over a few MB of harmless zero bytes)
  with `timeout=1` → `TIMEOUT`, never clean. If you cannot make it slow
  enough reliably, inject a scanner double that raises `yara_x.TimeoutError`
  and say which you did.
* **Compile warning** recorded in the manifest (e.g. a rule that triggers a
  YARA-X slow-pattern or unused-variable warning).
* A **source with an error** recorded as rejected while the other sources
  still load (`RULES_DEGRADED`).
* The same JSON rule in a **bundled** pack → `SUPPORTING`, in the **user**
  pack → `CONCLUSIVE`.
* **End to end clean**: core + JSON + YARA-X over a harmless synthetic file
  through the orchestrator; assert the verdict and the `trusted_clean` value
  M1 policy gives, and explain it in a comment.

## Running the tests

`..\sentinel-guard\.venv\Scripts\python -m pytest -q tests/gate_v2 -p no:cacheprovider`
If the sandbox refuses temp folders, report it and stop; create no folders.

## Your answer

English, concise: per item, change (file:line) and test name; the exact
command and real output.
