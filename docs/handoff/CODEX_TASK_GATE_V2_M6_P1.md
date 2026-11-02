# Codex task — Gate v2 milestone 6, part 1: cache and legacy projection (pure modules)

You are writing the two pure modules of milestone 6. Claude reviews every line,
runs the tests and merges. **Part 1 wires nothing**: `engine/scanner.py`, `db.py`
and all callers stay untouched (part 2). Read the review tables of milestones 1–4
in `REVIEWS.md` (F, G, H, J) first and do not repeat them.

## Pinned start

Worktree `..\sentinel-guard-gate-v2-m6`, branch `codex/gate-v2-m6`, start commit
**0215d8e**; otherwise stop and report.

## Allowed paths

Exactly four new files: `agent/sentinel/gate_v2/cache.py`,
`agent/sentinel/gate_v2/legacy.py`, `tests/gate_v2/test_m6_cache.py`,
`tests/gate_v2/test_m6_legacy.py`. Everything else is read-only: `contract.py`,
`policy.py` and `orchestrator.py` are being changed in another worktree right now,
so depend only on their public names. Do not commit.

**Sandbox note:** you cannot run pytest in this sandbox (temp folder denied). That
is *not* a reason to stop: implement everything, re-read your code against each
test, and say which test covers what. Never create temp or probe folders. Claude
runs the suites.

## Read first

R11 §2 (invariants 1, 7, 12, 13), §3 "Cache rules" and "Compatibility adapter",
§6; `PROJECT_CONTEXT.md` §11 R2; `contract.py`; `policy.py` (`decide`, how
`cacheable` is computed); `engine/verdict.py`; `engine/scanner.py:58-168`;
`db.py:450-470`; and each consumer below.

## `cache.py`

1. `GenerationInputs` (frozen dataclass): `policy_version`, `contract_version`,
   `core_version`, `analyzer_versions: tuple[tuple[str, str], ...]`,
   `rule_digests: tuple[tuple[str, str], ...]` (engine id, ruleset digest),
   `known_bad_generation: str`, `clamav_generation: str | None`,
   `clamav_state`, `defender_state`, `exception_generation: str`, and
   `disabled_by_policy: tuple[str, ...]`. `clamav_state` is one of `verified`,
   `not_installed`, `disabled_by_policy`, `unavailable`; `defender_state` one of
   `active`, `passive`, `not_installed`, `disabled_by_policy`, `unknown`.
2. `gate_generation(inputs) -> str`: SHA-256 of canonical JSON, independent of
   tuple order. Two rule sets of equal count but different digests give different
   generations; a rule **count** is not an input. `exception_generation` changes
   it: invariant 12 and 13.
3. `cache_class(decision) -> Literal["long", "short", "none"]` per the R11 §3 table:
   `decision.cacheable` false → `none`; `malicious` with accepted evidence or
   `clean` with `trusted_clean` → `long`; `suspicious` → `short`; fixed-partial or
   reduced `clean` → `short`, staying `trusted_clean=False`. Any stage status of
   `timeout`, `changed`, `cancelled`, `unverified`, `error`, or `runtime_partial`
   coverage → `none`, even if `cacheable` says otherwise (a second lock, tested).
4. `CacheStore` Protocol: `get(key) -> str | None`, `put(key, payload, expires_at)`.
   Part 2 implements it on `Database`; tests use an in-memory fake.
5. `cache_key(identity, gate_generation) -> str`: SHA-256 over the content hash,
   volume serial, file id, size, mtime, change time, canonical path and generation.
   `None` identity or no file id → no key, not an error.
6. `store(cache, decision, now)`, `lookup(cache, identity, gate_generation, request,
   now) -> FinalDecision | None`:
   * Never store `action_decision`: action is recomputed every time, because
     protection generation and identity are current facts (invariants 10, 11).
   * A hit returns the same verdict, `trusted_clean`, `policy_scope`, reasons and
     accepted evidence; only `scan_id` and every `file_id` are rebound to the
     request. It can never strengthen anything (invariant 12).
   * Serialise with `to_dict`/`from_dict`. Reject payloads above 256 KiB on store.
     A corrupt, oversized, expired, wrong-version or wrong-identity payload is a
     miss; `lookup` never raises.
   * TTLs are named constants: long = 30 days (matches `db.SCAN_CACHE_MAX_AGE`),
     short = 1 hour.

## `legacy.py`

`Verdict` stays the shape callers use. `label` is a read-only property there, so:

1. `UNKNOWN = "unknown"` and `@dataclass class GateVerdict(Verdict)` with
   `decision: FinalDecision | None = None` and a private count of projected findings.
2. `label`: from `decision.verdict`, including `unknown`. One exception: a finding
   with severity `CRITICAL` **appended by a caller after projection** gives
   `malicious`. `nativehost.on_scan_download` does that for a blocklisted download
   URL, and owner question 2 keeps that behaviour until the owner decides.
   Projected findings never change the label: an unaccepted Defender hit stays
   `unknown`.
3. `score` stays display metadata (inherited).
4. `to_dict(max_findings=200)`: every existing key plus `scan_result`, a compact
   summary: contract version, verdict, trusted_clean, policy_scope, reason codes,
   accepted evidence ids, gate generation, duration, and per stage engine id,
   status, verdict, readiness code, coverage mode. No paths, no raw names, no
   evidence bodies; under 64 KiB in the worst case, tested. Native messages over
   1 MB kill the connection (`nativehost.py:30,249-254`).
5. `project(decision, *, name, path, stage_defaults) -> GateVerdict`, where
   `stage_defaults: dict[str, str]` gives the text for an engine with no stage
   (`"unavailable: off or not the active antivirus"`).

**`engines`** — keys are exactly `sentinel` (core), `rules+yara` (json_rules +
yara_x, worst case wins, `detected` beats all), `clamav`, `defender`.
`tests/test_gate.py:139` asserts the set. Analyzers are not projected. `clamav`
appears only if it ran or `stage_defaults` names it. Values keep the prefixes
consumers parse: `scanjob.CHECKED`, `__main__.py:48`, `gate_ui.layer_text`:

| Stage | Text |
|---|---|
| completed, no evidence | `clean` |
| evidence (accepted or not) | `detected` |
| partial | `partial: <code>` |
| skipped after a hit | `skipped: already detected` |
| skipped, other | `skipped: <code>` |
| unavailable | `unavailable: <code>` |
| unverified | `unavailable: unverified daemon` |
| error, changed | `error: <code>` |
| timeout | `timeout: <code>` |
| cancelled | `skipped: cancelled` |

**`skipped`** — from the top reason. The strings are parsed by
`watcher.py:181,184`, `scanjob.py:157`, `__main__.py:43`:

| Reason | Text |
|---|---|
| `CHANGED` | `changed while scanning` (exact) |
| `IN_USE` | `unreadable: in use by another program` |
| `UNREADABLE` | `unreadable: cannot open` |
| `NOT_REGULAR` | `not a regular file` (exact) |
| `TOO_LARGE` | `too large to scan` |
| `CANCELLED` | `cancelled` |
| other incomplete reasons | `incomplete: <code>` |
| clean, malicious, suspicious with full coverage | `None` |
| `FIXED_PARTIAL`, `REDUCED_POLICY` | `partial: <code>` |

A decision with no engine results (identity failure) projects with `sha256=""`,
`size=0`, and the reason's text. `IN_USE` must keep the watcher's retry (RT-016).

**`findings`** — one per evidence item, keeping these rule ids so that existing
tests and UI text keep working:

| Evidence | Finding (engine, rule) |
|---|---|
| core `EICAR` | `signature`, `eicar.test_file`, detail as in `signatures.py:71` |
| core `KNOWN_BAD_HASH` | `signature`, `hash.known_bad` |
| core `RTLO`, `DOUBLE_EXTENSION`, `PADDED_NAME`, `MISMATCH` | `filetype`, `filetype.<lower>` |
| core `PE_*`, `SCRIPT_INDICATOR` | `pe`, `pe.<lower without PE_>`; `script`, `script.indicator` |
| json_rules | `rules`, the rule id |
| yara_x | `yara`, `yara.<identifier>` |
| clamav | `clamav`, `clamav.detection`, or `clamav.<first name part lowered>` when weak; detail `ClamAV: <raw name>` |
| defender | `defender`, `defender.detection`, detail `Microsoft Defender: <name>` |
| analyzers | the engine id, `<engine>.<code lower>` |

Severity and score from strength: conclusive → `CRITICAL`, 100; strong → `HIGH`,
50; supporting → `MEDIUM`, 30; context and coverage → `INFO`, 0. `filetype.rtlo`
stays `HIGH`. `Finding.detail` is English. Member evidence prefixes `member_path:`.
Bounded: raw names stay within the contract's limits.

## Required tests

Cache: same-count rule swap changes the generation (R11 §8 row 6); each input
changes it; every row of the R11 table, including `not_installed`/`not_active`
reuse only when the generation still matches; `unknown` is never stored; hit
reproduces the decision and rebinds ids; `action_decision` is absent from the
payload; corrupt, expired, oversized, wrong-identity → miss without raising; a
reduced `clean` never returns as trusted.

Legacy: every row of the three tables; `to_dict` keeps all old keys and adds
`scan_result`; worst-case size; a caller-appended `CRITICAL` gives `malicious` and
a projected unaccepted one does not; `unknown` from each incomplete reason;
`Verdict` consumers' prefixes stay parseable (`startswith` on each exact prefix).

Decisions are built with `policy.decide` from hand-made `EngineResult`s. Harmless
synthetic data; no EICAR on disk; no network.

## Constraints

Python 3.12+, typed, stdlib only, small modules, comments explain why, LF.

## Your answer

English, concise: files and line counts, API, invariant → test mapping, and the
list of everything part 2 must do in `engine/scanner.py`, `db.py` and the callers,
including any old finding this projection cannot reproduce.
