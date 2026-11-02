# Codex task — Gate v2 milestone 3: core and rule adapters

You are the implementer of Gate v2 for Sentinel Guard. Claude reviews every
line, runs the tests and decides the merge. Milestones 1–2 are merged; read
their review records in `REVIEWS.md` ("Gate v2 milestone 1", "milestone 2") —
the same standards apply, and the findings there (F1–F8, G1–G8) are mistakes
not to repeat.

## Pinned start

Worktree `..\sentinel-guard-gate-v2`, branch `codex/gate-v2-m3`, start
commit **682ce56** (`git log -1 --format=%h`); otherwise stop and report.

## Allowed paths

`agent/sentinel/gate_v2/` and `tests/gate_v2/` only. New modules: `core.py`,
`rules.py`, and if you need it a `content.py` (see 1). M1/M2 modules may
change only where M3 needs it; list each change and why. Existing modules
outside `gate_v2/` (`engine/signatures.py`, `engine/filetype.py`,
`engine/scanner.py`, `yarafeed.py`, `config.py`, `db.py`) are **read-only**:
you may import pure helpers from them, never modify them. Integration into
the old scanner is milestone 6. Do not commit.

## Read first

R11 §§1 (current-code table), 2, 3, 5 (rows Sentinel core, JSON user rules,
YARA-X), 6, 7 (rows Core/container, Rules/YARA-X), 8 row 3;
`docs/research/R12a-yara-x.md` §§2, 4–6 (RT-037…RT-052);
`docs/research/R8b-*` §§2–3 (container limits); `PROJECT_CONTEXT.md` §§7, 11;
the current code paths you replace: `engine/scanner.py` (`_read`, ZIP
handling, PE checks), `engine/signatures.py`, `engine/filetype.py`,
`yarafeed.py`; and `docs/research/R13b-design-discussion.md` P4–P5: these
adapters will later run inside a **restricted low-privilege worker**, so they
must work from a supplied read-only handle/stream and never need write access,
network, or a writable temp directory.

## What to build

1. **Bound content access (one generation).** Adapters must not reopen the
   path. Provide a small reader bound to the measured `FileIdentity` (opened
   once, `fstat` checked against the identity, bounded `read(offset, n)`,
   resident-byte budget, cancellation between chunks); bytes requests use the
   same interface over memory. Wire it so the M2 orchestrator gives each
   adapter that reader (an additive change to how adapters are called, or a
   context object — your design, documented). Adapters that still need a
   path declare `reopens_path` as in M2.
2. **`core.py` — Sentinel core adapter** (`engine_id="core"`):
   * Built-in EICAR hash and a **known-bad hash lookup injected as a callable**
     (no DB import) → `CONCLUSIVE` malware evidence; EICAR sets
     `is_test_file=True`.
   * Filename deception, double extensions, PE structure (packed sections,
     entropy, certificate-table presence — **presence is not "signed"**,
     RT-052), script indicators → `SUPPORTING`/`CONTEXT` only (invariant 6).
     Reuse logic from `engine/filetype.py`/`scanner.py` where sound; keep
     detection functions total (hostile input never raises; malformed data
     becomes evidence or coverage, not an empty clean result).
   * ZIP inventory with the coverage ledger: every member is `inspected`,
     `opaque` (encrypted, unsupported method) or `omitted` (depth > 3,
     > 2,000 members, declared expansion > 256 MiB, member over the size
     budget) with a stable reason; a parse exception is `partial`/`error`,
     never "no finding". Existing limits: `config.py:14-17`.
   * Coverage: exact byte ranges actually read; `certainty="verified"` only
     for what this adapter itself read and parsed.
3. **`rules.py` — JSON user rules and YARA-X** (one adapter each, or one
   adapter with two engine IDs — but every engine ID yields exactly one result):
   * JSON packs: strict schema, per-pack SHA-256 digest, accepted/rejected
     manifest with reasons; a malformed pack is a typed degraded state
     (`PARTIAL`/`UNAVAILABLE` + readiness code), not a silent skip.
     Locked policy (`PROJECT_CONTEXT.md` §7.5): only a **user** rule pack
     (from the user rules directory, passed in explicitly) with
     `severity: critical` is `CONCLUSIVE`; bundled or other rules are
     `SUPPORTING`. The test marker rule in `tests/conftest.py` is such a user
     critical rule.
   * YARA-X (`yara_x` is installed in the venv; skip tests with a reason if it
     is missing): compile once from sources passed in, keep the compiled
     `Rules` shareable and create **one `Scanner` per worker thread**; record
     namespace, rule identifier, tags, metadata, source digest, compile
     warnings/errors/ignored rules in a manifest; set a timeout and
     `max_matches_per_pattern`; `TimeoutError`/scan errors become typed
     `TIMEOUT`/`ERROR` (RT-037), never clean; a degraded ruleset is an explicit
     readiness state. A YARA Forge hit is at most `STRONG`/`SUPPORTING` →
     final verdict at most suspicious (R11 §6). Whole-file scanning only from
     the bound reader; if you keep a front/tail split for large files, its
     coverage is `fixed_partial` and must not pretend `filesize`/offsets refer
     to the original file (R12a §4).
   * A **ruleset digest** (content, not counts — RT-009/RT-033 lesson) exposed
     for the future `gate_generation`.

## Required tests (`tests/gate_v2/`)

Harmless synthetic inputs only; EICAR only as in-memory bytes (use
`tests/conftest.py`'s `EICAR`), never written to disk; the marker rule for
on-disk positives; files under `tmp_path`; no network.

* Core: EICAR bytes → conclusive + test file; injected known-bad hash →
  conclusive; double extension / packed PE (synthetic header bytes) →
  supporting only, verdict ≤ suspicious; malformed PE never raises.
* ZIP (built with `zipfile` in tmp_path): encrypted member flag, unsupported
  method, malformed central directory, 2,001 entries, depth four, oversize
  member, expansion budget — each has its omitted/opaque reason; injected
  parser exception → not clean.
* Rules: malformed pack → degraded, others still load; user critical marker →
  conclusive; same rule in a non-user pack → supporting; digest changes when
  one byte of a rule changes but the rule count does not.
* YARA-X: duplicate rule names in two namespaces both reported; compile
  warning recorded; a source with an error is reported as rejected; timeout
  (tiny timeout + slow synthetic rule) → `TIMEOUT`; match cap respected;
  scanner per thread (two threads, no shared `Scanner`).
* Bound reader: file swapped after measurement → reader refuses (`CHANGED`);
  resident budget respected; cancellation between chunks.
* End to end through the M2 orchestrator with core + rules adapters on the
  marker file → `malicious`; on a clean synthetic file with all stages
  complete → `clean` and `trusted_clean` per M1 policy (coverage permitting).

## Running the tests

`..\sentinel-guard\.venv\Scripts\python -m pytest -q tests/gate_v2 -p no:cacheprovider`
If the sandbox denies the temp directory, say so and stop; do **not** create
probe or temp folders. Claude runs everything outside the sandbox.

## Constraints

Python 3.12+ (venv 3.15), typed, stdlib + `yara_x` only, small modules,
comments explain why, LF endings. Stricter reading when R11 is ambiguous; list
ambiguities.

## Your answer

English, concise: files and line counts, API, invariant/RT → test mapping,
changes to M1/M2 files and why, the exact pytest command and its real output,
and open points for milestones 4–6.
