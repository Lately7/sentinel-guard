> **Claude note (2026-11-02).** Codex gpt-6-sol, high, read-only synthesis of R5-R12. This is the
> specification Codex will implement Gate v2 from (owner decision). It is a proposal until the owner
> settles section 9; milestone 1 (schema + pure policy) can start without those answers.

# R11 — Gate v2 knowledge pack and implementation specification

**Status:** proposed design, read-only research round. No repository files were changed. I read the research, handoffs, roadmap, and current scan path; I ran source searches and `git status`, but did **not** run a scan or test suite. The current branch was `gate-baseline` with pre-existing changes in `extension/src/popup.js`, `extension/src/page_status.js`, and `extension/test/page_status.test.mjs`.

**Authority rule:** current code describes what exists; [PROJECT_CONTEXT.md](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/docs/handoff/PROJECT_CONTEXT.md>) §§7, 10–11 and [ROADMAP.md](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/docs/ROADMAP.md>) describe locked product decisions. Everything marked **Proposal** below is a Gate v2 design choice for implementation review.

## 1. Knowledge digest

| Constraint | Documented fact | Gate v2 consequence |
|---|---|---|
| A clamd reply is narrow | `INSTREAM` returns an ordinary `OK`, one `FOUND` name, or `ERROR`; it does not identify matched database record, omitted members, parser failures, or active reload generation. R8a §§2, 4–5; R8c §§2–4. [ClamAV protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html). | Store transport result separately from claimed coverage. Never infer recursive completeness from `OK`. |
| ClamAV normalizes failures | `CL_EFORMAT`, `CL_EPARSE`, `CL_EREAD`, `CL_EUNPACK`, `CL_EMAXSIZE`, `CL_EMAXFILES`, and `CL_EMAXREC` can be converted to `CL_SUCCESS` at parser/layer boundaries; top-level files over `MaxFileSize` may yield `OK` when `AlertExceedsMax` is off. R8a §5; R8b §2. | Independent container inventory must mark opaque or omitted children. A clean clamd transport result cannot clear that debt. |
| ClamAV names do not expose mechanism | Hash, body, logical, container, bytecode, and ClamAV YARA loaders all supply names. `.UNOFFICIAL` identifies load provenance, not match quality. R8c §2. | Keep raw name and database generation; do not claim “known-bad hash” from name spelling. |
| Weak ClamAV classes | ClamAV internally treats `PUA.*`, `Heuristics.*`, and `BC.Heuristics.*` as potentially unwanted; `Weak.*` is nonalerting internally. R8a §4; R8c §2. Current Sentinel only downgrades the first two (`agent/sentinel/engine/clamav.py:228-233`). | Weak-prefix policy precedes any family-name interpretation. Limit and encrypted alerts are coverage evidence. |
| ClamAV freshness is multidimensional | `PING` proves liveness; `RELOAD` answers before activation; `VERSION` exposes engine and active daily database metadata, not every database or local rule. R8c §§3–4. | Readiness needs daemon, database, configuration, freshness, and reload-generation fields. |
| Container support is conditional | ClamAV has parsers for ZIP, RAR, 7z, OLE2, PDF, mail, and many other formats, but encrypted members, unsupported ZIP/7z methods, malformed records, and limits can leave children uninspected. LNK receives no semantic parser in the reviewed dispatch; MSIX is treated through generic ZIP extraction. R8b §§2–3. | Track child objects and parser state explicitly; add bounded LNK/package analyzers. |
| YARA-X scanners are per worker | The reviewed Python `Scanner` is unsendable; compiled `Rules` can be shared across scanners. `Scanner.scan_file()` supports pathname input, timeout, and match caps; `TimeoutError` returns no `ScanResults`. R12a §§2, 4. [YARA-X Python API](https://virustotal.github.io/yara-x/docs/api/python/). | One scanner instance per file worker; timeout is incomplete, never a negative result. |
| YARA-X rule loading can degrade | Compile diagnostics and ignored rules are available; a source with an error can still contribute compiled rules. Match results expose namespace, identifier, metadata, and offsets, which Sentinel currently discards (`agent/sentinel/engine/signatures.py:85-94,121-139`). R12a §§2, 5–6. | Pin a content digest and accepted/rejected manifest; a degraded ruleset is an explicit readiness state. |
| Forge score is not calibrated probability | Forge package thresholds are selection criteria; a high score does not supply a measured false-positive probability. R12a §5. | Forge hits remain suspicious unless a specific rule is independently promoted after clean-corpus review. |
| Structural capability is not malice | capa rules can match APIs, constants, strings, and combinations within static scopes; several cited capabilities are ordinary in legitimate programs. Its static path can be costly and has no CLI-wide deadline in the reviewed path. R12b §§2–4. | capa is optional explanation only, as locked in `PROJECT_CONTEXT.md` §7; never change verdict or action from its output. |
| Smart-scan enumeration can omit entries | The reviewed osquery tables sometimes return empty rows after access or parse failures; registry default view is process dependent; task-folder discovery through `System32\Tasks` can miss COM-visible folders. R12c §§1, 4. | Scope discovery produces source-entry coverage, including denied and unresolved entries. A successful scan of discovered files alone does not certify a smart scan. |
| Windows signer trust needs a distinct check | A PE certificate-table entry is not trust verification (`agent/sentinel/engine/scanner.py:355-376`). YARA-X verifies embedded cryptographic relationships but not Windows chain/revocation trust (R12a §3). Catalog membership requires member information in `WINTRUST_CATALOG_INFO` (R12c §2). [Microsoft catalog member structure](https://learn.microsoft.com/en-us/windows/win32/api/Wintrust/ns-wintrust-wintrust_catalog_info). | Treat signer state as context, never an allow verdict. Bind the check to the scanned file generation. |
| Watch events are hints | Current watcher debounces by path, with an unbounded pending dict and no active-scan stop barrier (`agent/sentinel/watcher.py:40,49-60,73-99,285-289`). Wazuh’s reviewed FIM flow separately accounts for notifications, reconciliation, alerts, and action; its privileged who-data path does not fit this no-admin agent. R12d §§2, 5. | Bounded queue, retry debt, reconciliation, and action-generation barrier. Do not promise pre-open blocking or writer-process attribution. |
| Commercial names are not scores | Public vendor documents do not publish a universal file-by-file decision tree or a complete failure-to-verdict contract. PUA controls and action modes are distinct from malware detection. R9 introduction, §§1–7. [Malwarebytes scan settings](https://help.malwarebytes.com/hc/en-us/articles/41813847845275-Malwarebytes-for-Windows-scan-settings), [Microsoft PUA policy](https://learn.microsoft.com/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus). | Use Sentinel’s own versioned evidence and action rules; do not infer probability from a vendor name. |
| Static file scope has hard limits | R10 §§1, 3–6 separates bytes and metadata visible at scan time from later execution, memory-only stages, remote stages, and kernel state. Current watcher scans after events (`agent/sentinel/watcher.py:82-99`). | Report “not assessed” scope precisely. Gate v2 cannot attest to a safe running process, boot chain, or remote page. |
| Low false-positive operation is a release requirement | R7 evaluation section calls for temporal separation, low-FPR reporting, a realistic clean corpus, and separate static versus whole-product claims. R10 §6 item 15 requires an owner-machine clean-software baseline. | Freeze policy and engine generations before measurement; reject an update that exceeds the agreed clean-corpus alert budget. |

### Current code that the replacement must correct

| Current behavior | Source | Required replacement |
|---|---|---|
| `Verdict.label` is `malicious` for any `CRITICAL` finding or score ≥70, `suspicious` at ≥30, otherwise `clean`; it does not inspect statuses or coverage. | `agent/sentinel/engine/verdict.py:52-72` | Typed final decision from evidence **and** completion. |
| `_read()` hashes the statted size but retains up to 64 MiB; oversized rules get independent front/tail buffers, and ClamAV reopens the path. | `agent/sentinel/engine/scanner.py:79-105,189-219,386-406`; `agent/sentinel/config.py:14-17` | One held file generation; every reopened/path-based stage revalidates identity and content binding. |
| Oversized ZIP member scanning can clear `v.skipped` after one pass, while parser exceptions may return no finding. | `agent/sentinel/engine/scanner.py:106-119,236-306` | Coverage ledger independent of findings, with per-member omitted reasons. |
| Cache identity uses rule counts and a clamd version string; incomplete results are stored. | `agent/sentinel/engine/scanner.py:58-65,86-93,152-168` | Content-digest gate generation and status-aware cacheability. |
| YARA-X exceptions are logged and swallowed. | `agent/sentinel/engine/signatures.py:85-94` | Typed `timeout` or `error`; no clean rules result. |
| Defender scans a path later; exit `2` is accepted only with a `Threat:` name. | `agent/sentinel/engine/defender.py:107-133` | Preserve the conservative return-code parsing and add before/after file-generation checks. |
| `act_on()` quarantines from aggregate `v.label`; quarantine verifies copied SHA-256 only after renaming. | `agent/sentinel/protection.py:23-42`; `agent/sentinel/quarantine.py:64-97` | Separate action decision, identity check, and transactional action outcome. |
| Restore defaults to global hash trust. | `agent/sentinel/quarantine.py:110-143`; `agent/sentinel/db.py:438-442` | Restore creates only the locked path+hash exception; explicit Trust has its own operation. |
| Native download handling can add a critical URL-origin finding to the file verdict. | `agent/sentinel/nativehost.py:137-153` | Keep URL provenance as a distinct, authenticated evidence channel with explicit policy and file binding. |

## 2. Gate v2 invariants

The following are **Proposal** acceptance properties, constrained by the locked decisions in `PROJECT_CONTEXT.md` §§7, 10–11.

1. **No false clean:** if a required, applicable stage is `partial`, `unavailable`, `error`, `timeout`, `cancelled`, `unverified`, or `changed`, final `trusted_clean` is false. If there is no accepted detection, final verdict is `unknown`.
2. **One file generation:** every accepted engine result names the same `file_id`, volume/file identity, size, and SHA-256 as the request’s measured generation. A pathname-only result is rejected after any before/after identity mismatch.
3. **Evidence integrity:** an unverified engine or daemon can supply a notify-only lead, never clean coverage or automatic quarantine authority.
4. **Independent axes:** `EngineResult.status`, `EngineResult.verdict`, `FinalDecision.verdict`, `trusted_clean`, and `ActionDecision.action` are stored separately. No string prefix or summed severity is an implicit action rule.
5. **Conclusive sufficiency:** one accepted conclusive local signature, accepted ClamAV conclusive name, or named Defender threat may establish `malicious`; a missing second opinion does not erase that hit.
6. **Weak-signal restraint:** a Forge hit, PUA, generic heuristic, capability, entropy, filename anomaly, unsigned signer state, or MotW alone cannot establish `malicious` or auto-quarantine.
7. **Coverage accounting:** every enabled stage emits a result, including a typed skip reason after an earlier conclusive hit. Every known omitted child/member is represented; failure to enumerate a container is `partial` or `error`.
8. **Bounded work:** a file, child, archive, rule match list, event queue, and source enumeration each has byte/count/time limits. Hitting a limit produces explicit incomplete coverage.
9. **Cancellation is terminal:** cancellation stops new work and marks unfinished files `cancelled`; they are never cached. Already accepted conclusive detections complete an action decision; an action in progress finishes or rolls back.
10. **Action binds to current bytes:** immediately before quarantine, the target must still resolve to the measured generation and hash. A mismatch yields `CHANGED_BEFORE_ACTION` and schedules a rescan.
11. **Stop barrier:** disabling real-time protection revokes its generation before any later automatic action. “Off” is published only after the action boundary is closed.
12. **Cache cannot strengthen evidence:** cache reuse may reproduce only the original decision under the same policy and engine generations. It cannot turn `unknown`, `partial`, or reduced-policy `clean` into trusted clean.
13. **Exceptions are scoped:** Restore’s exception is path+hash. An exception does not rewrite historical evidence or imply the file was scanned clean.
14. **Portable event privacy:** `ScanEvent` contains no path, hash, URL, username, command line, or raw engine output by default.
15. **Scope honesty:** a per-file clean result does not certify inaccessible smart-scan sources, running memory, live kernel, firmware, or prevention before execution.

## 3. Architecture

### Modules and ownership

**Proposal.** New files live under `agent/sentinel/gate_v2/` until the adapter has passed regression review.

| Module | Owns | Does not own |
|---|---|---|
| `contract.py` | Versioned immutable request/result/evidence/coverage/event types; validation and serialization. | Detection policy. |
| `identity.py` | Handle-based canonical path, volume/file ID, stat generation, chunked SHA-256, pre/post checks. | Quarantine. |
| `coverage.py` | Byte-range union, container/member ledger, opaque-object reasons, policy completeness. | Threat strength. |
| `core.py` | Existing hash, name, PE and ZIP checks adapted to structured output. | Aggregate verdict. |
| `rules.py` | JSON rules and YARA-X compiler manifest, per-worker scanner, diagnostics, match provenance. | Trusting arbitrary rule metadata. |
| `clamd.py` | Strict framed client, private-daemon verification, active database/config generation, INSTREAM. | Inferring internal parser completeness from `OK`. |
| `defender.py` | Active/readiness check and pathname scan with generation checks. | File quarantine. |
| `analyzers/` | Bounded non-executing LNK, script, container/document, package, PE/.NET structure, MotW, signer/context observations. | Malware verdict from a single capability. |
| `policy.py` | Deterministic evidence acceptance and final verdict; policy version and reason codes. | File mutation. |
| `actions.py` | `should_auto_quarantine`, protection-generation barrier, pre-action verification, action audit. | Detector implementation. |
| `cache.py` | Gate-generation digest, cacheability predicate, lookup and invalidation. | Unverified negative evidence. |
| `events.py` | Bounded progress channel and durable terminal-event ledger. | UI widgets. |
| `orchestrator.py` | Per-file stage order, deadlines, cancellation, worker pools, and result assembly. | Rendering. |
| `legacy.py` | Compatibility projection to existing `Scanner`/`Verdict` callers. | Independent classification. |
| `scope.py` | Smart/deep source discovery with source-entry coverage and file dedupe. | File malware classification. |

### Data flow and state machine

```text
source discovery -> admission -> open/identify -> hash and snapshot
    -> core -> rules/YARA-X -> ClamAV -> Defender
    -> optional structural/context analyzers -> policy
    -> action policy -> pre-action revalidation -> action outcome
    -> cache decision + terminal event
```

Stages of **one file** are sequential. Different files run concurrently. The locked starting point is two file workers, maximum four; ClamAV concurrency two or three; Defender pool one; weighted in-flight byte budget about 192–256 MiB (`PROJECT_CONTEXT.md` §10). **Proposal:** hold the same opened file handle for hashing and byte-consuming stages. A path-only adapter must compare volume/file ID, size, change time, and SHA-256 before and after; metadata equality without byte binding is insufficient. Windows `FILE_ID_INFO` and `GetFinalPathNameByHandleW` support handle-based identity. [Microsoft file ID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info), [final path](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew).

| State | Allowed next state | Terminal result if interrupted |
|---|---|---|
| `queued` | `opening`, `cancelled` | `cancelled` |
| `opening` | `hashing`, `unknown` | `unavailable`/`error` |
| `hashing` | `core`, `unknown`, `cancelled` | `changed`, `timeout`, `cancelled` |
| `core` / `rules` / `clamav` / `defender` | next stage, `deciding`, `cancelled` | current accepted evidence retained; incomplete coverage |
| `deciding` | `action_pending`, `complete` | deterministic final decision |
| `action_pending` | `acting`, `complete` | reason-coded no-action or approved action |
| `acting` | `complete`, `action_failed` | finish or rollback; never leave an unrecorded half-action |
| `complete` / `action_failed` / `cancelled` | none | immutable result |

### `ScanEvent` stream

The event schema follows `PROJECT_CONTEXT.md` §10: `event_version`, `scan_id`, opaque scan-local `file_id`, monotonic `sequence`, `stage`, `state ∈ {started, finished, skipped, error, cancelled}`, `duration_ms`, and `result_code`. **Proposal:** add `counters_delta` as a bounded map of named integers; keep path resolution in a local UI lookup keyed by `file_id`. CLI JSONL includes paths only with `--include-paths`.

A worker writes routine progress into a bounded, coalescing queue and updates worker-side counters. UI reads snapshots at about 10 Hz. Detection, error, and action terminal events go into a durable ledger before delivery; admission pauses when its quota is exhausted, so workers do not block on a paused consumer and terminal events are not lost. The required 500,000-event paused-consumer test must verify bounded memory and nonblocking worker publication. This design takes the “never drop terminal events” and “bounded queue” requirements together (`PROJECT_CONTEXT.md` §10).

### Cache rules

| Result/readiness class | Cacheable? | Reuse condition |
|---|---:|---|
| `malicious` with accepted evidence, or completed full-policy `clean` | Yes | Same content SHA-256 and file generation, policy version, rule source digest, ClamAV active DB/config generation, Defender applicability, and exception generation. |
| `suspicious` from completed, deterministic evidence | Yes, short-lived | Same full key; readiness rechecked. |
| Fixed `partial_by_policy` ranges | Yes, short-lived | Remains partial and `trusted_clean=false`; no promotion. |
| `disabled_by_policy` | Yes | Only under the same reduced policy; never full-policy trusted clean. |
| `not_installed` / `not_active` | Conditional | Re-evaluate availability before reuse, as locked in `PROJECT_CONTEXT.md` §11. |
| `not_running`, `starting`, `connection_error`, `timeout`, runtime partial, changed, cancelled, unverified daemon, degraded ruleset | No | Rescan. |

The current cache uses path, metadata, hash, and a weak `gate_id()` (`agent/sentinel/engine/scanner.py:58-65,86-93`; `agent/sentinel/db.py:450-462`). **Proposal:** calculate `gate_generation = SHA256(canonical serialized policy + accepted/rejected rule manifest and source digests + core/analyzer versions + ClamAV active inventory/config digest + Defender applicability contract + exception generation)`. A rule **count** never participates as a substitute for content identity.

### Compatibility adapter

Retain `agent.sentinel.engine.scanner.Scanner` with its constructor and `scan_file(path, *, use_cache=True)` / `scan_bytes(data, name="<memory>")` signatures (`agent/sentinel/engine/scanner.py:36-50,69,155`). Its methods call `GateV2.scan()` and project the result into `Verdict`, adding a private `decision` reference or additive `scan_result` field. The adapter must expose:

- `label` from `FinalDecision.verdict`, including `unknown`;
- `engines` strings from structured engine results;
- `skipped` from top incomplete reason;
- `score` only as display metadata, never policy input;
- `to_dict()` with existing keys **plus** `scan_result` contract v2.

`scanjob.py`, watcher, CLI, tray, and native host currently consume the old fields (`agent/sentinel/scanjob.py:108-173`; `agent/sentinel/watcher.py:91-99`; `agent/sentinel/__main__.py:25-74`; `agent/sentinel/nativehost.py:137-153`; `agent/sentinel/tray.py:60`). Change `protection.act_on()` to prefer the attached typed decision and reject a legacy `Verdict` that lacks verified action provenance; adjust callers before enabling Gate v2. The native response adds `scan_result` while preserving existing keys (`agent/sentinel/nativehost.py:137-153`).

## 4. Versioned Python contracts

The following is the **proposed exact public shape** for `contract_version=2`, `policy_version="evidence-v1"`, and `event_version=1`. Internal adapters may use protocols, but serialized names and semantics must remain stable.

```python
from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol

CONTRACT_VERSION = 2
EVENT_VERSION = 1

class StageStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    UNVERIFIED = "unverified"
    CHANGED = "changed"

class VerdictCode(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"

class Strength(StrEnum):
    CONCLUSIVE = "conclusive"
    STRONG = "strong"
    SUPPORTING = "supporting"
    CONTEXT = "context"
    COVERAGE = "coverage"

class Category(StrEnum):
    MALWARE = "malware"
    PUA = "pua"
    RISKWARE = "riskware"
    STRUCTURE = "structure"
    ORIGIN = "origin"
    HEALTH = "health"

class ActionCode(StrEnum):
    NONE = "none"
    NOTIFY = "notify"
    REVIEW = "review"
    QUARANTINE = "quarantine"
    RETRY = "retry"

@dataclass(frozen=True)
class ByteRange:
    start: int                 # inclusive
    end: int                   # exclusive, start <= end

@dataclass(frozen=True)
class FileIdentity:
    canonical_path: str | None
    volume_serial: int | None
    file_id_hex: str | None    # 128-bit Windows FILE_ID_INFO, if available
    size: int
    sha256: str                # lowercase 64 hex chars after complete hash
    change_time_ns: int | None
    mtime_ns: int | None

@dataclass(frozen=True)
class Coverage:
    input_size: int
    inspected: tuple[ByteRange, ...]      # sorted, nonoverlapping outer-file ranges
    mode: Literal["full", "fixed_partial", "runtime_partial", "none"]
    objects_seen: int
    objects_inspected: int
    objects_opaque: int
    objects_omitted: int
    object_reasons: tuple[str, ...]       # bounded stable reason codes
    parser_states: tuple[tuple[str, str], ...]
    limits_hit: tuple[str, ...]
    certainty: Literal["verified", "declared", "unknown"]

@dataclass(frozen=True)
class Evidence:
    evidence_id: str                     # stable engine + source + signature ID
    engine_id: str
    signature_id: str | None
    raw_name: str | None                  # bounded, untrusted text
    category: Category
    strength: Strength
    scope: Literal["outer", "member", "origin", "system"]
    member_path: str | None               # bounded display context
    ranges: tuple[ByteRange, ...]
    source_id: str
    source_digest: str | None
    correlation_group: str | None
    verified: bool
    detail_code: str
    is_test_file: bool = False

@dataclass(frozen=True)
class ScanError:
    code: str                             # stable machine-readable code
    operation: str
    message: str                          # bounded/sanitized
    retryable: bool

@dataclass(frozen=True)
class EngineResult:
    contract_version: Literal[2]
    engine_id: str
    file_id: str                          # opaque scan-local ID
    identity: FileIdentity
    status: StageStatus
    verdict: VerdictCode
    coverage: Coverage
    evidence: tuple[Evidence, ...]
    engine_version: str | None
    db_version: str | None
    generation_digest: str | None
    readiness_code: str
    started_monotonic_ns: int
    duration_ms: int
    error: ScanError | None

@dataclass(frozen=True)
class ScanRequest:
    contract_version: Literal[2]
    scan_id: str
    file_id: str
    path: str | None
    data: bytes | None                    # exactly one of path/data
    source: Literal["cli", "watcher", "download", "on_demand", "test"]
    profile: Literal["smart", "deep", "single_file", "memory"]
    policy_version: str
    action_policy_version: str
    deadline_monotonic_ns: int
    protection_generation: int | None
    use_cache: bool
    include_paths_in_events: bool = False

@dataclass(frozen=True)
class FinalDecision:
    contract_version: Literal[2]
    scan_id: str
    file_id: str
    identity: FileIdentity | None
    verdict: VerdictCode
    trusted_clean: bool
    policy_scope: Literal["full", "reduced"]
    reason_codes: tuple[str, ...]
    accepted_evidence_ids: tuple[str, ...]
    engine_results: tuple[EngineResult, ...]
    cacheable: bool
    gate_generation: str
    duration_ms: int

@dataclass(frozen=True)
class ActionDecision:
    contract_version: Literal[2]
    action_policy_version: str
    action: ActionCode
    reason_code: str
    evidence_ids: tuple[str, ...]
    file_id: str
    expected_identity: FileIdentity | None
    protection_generation: int | None
    requires_revalidation: bool

@dataclass(frozen=True)
class ScanEvent:
    event_version: Literal[1]
    scan_id: str
    file_id: str | None
    sequence: int
    stage: str
    state: Literal["started", "finished", "skipped", "error", "cancelled"]
    duration_ms: int | None
    result_code: str
    counters_delta: tuple[tuple[str, int], ...] = ()

class CancellationToken(Protocol):
    def cancelled(self) -> bool: ...

class EngineAdapter(Protocol):
    engine_id: str
    def readiness(self) -> str: ...
    def scan(self, request: ScanRequest, identity: FileIdentity,
             cancel: CancellationToken) -> EngineResult: ...

def scan(request: ScanRequest, *, cancel: CancellationToken,
         emit: callable | None = None) -> FinalDecision: ...

def decide(results: tuple[EngineResult, ...], request: ScanRequest,
           gate_generation: str) -> FinalDecision: ...

def should_auto_quarantine(decision: FinalDecision, *,
                           policy_version: str,
                           auto_quarantine: bool,
                           protection_generation: int | None) -> ActionDecision: ...
```

Validation rules: reject negative sizes or durations; overlapping/out-of-bounds ranges; duplicate engine IDs; missing file identity for a claimed completed path scan; `COMPLETED` with an error; `CLEAN` from a stage whose status is not `COMPLETED`; conclusive evidence whose `verified` is false; and an unknown contract version. `Coverage.certainty="declared"` records an engine’s self-report and never by itself proves all nested objects were inspected.

## 5. Engine-adapter contracts

| Adapter | Input and readiness | Output and evidence strength | Limits/failure rule |
|---|---|---|---|
| Sentinel core | Held bytes/handle, full SHA-256, name and bounded header; known-bad DB generation and built-in test-file hash. Current `SignatureEngine.match_hash()` handles EICAR and DB hashes (`agent/sentinel/engine/signatures.py:69-77`). | Verified known-bad hash and EICAR: `CONCLUSIVE`; filename deception, PE structure, entropy: `SUPPORTING`/`CONTEXT` (`agent/sentinel/engine/filetype.py:80-107`; `agent/sentinel/engine/scanner.py:340-379`). | Hash read/change error is `ERROR`/`CHANGED`; ZIP limits and parse exceptions become coverage debt, not empty findings (`agent/sentinel/engine/scanner.py:236-306`). Existing initial budgets are 64 MiB retained body, ZIP depth 3, 2,000 members, 256 MiB declared expansion (`agent/sentinel/config.py:14-17`). |
| JSON user rules | Parse every source with strict schema, origin, digest and accepted/rejected count. Current loader skips malformed packs and allows `severity` metadata (`agent/sentinel/engine/signatures.py:37-59`). | Only an explicitly user-authored, **critical**, versioned and locally validated rule is conclusive under the locked policy (`PROJECT_CONTEXT.md` §7). Other rules are supporting. | Compile/load failure: `PARTIAL` or `UNAVAILABLE`; rule count cannot stand in for digest. No rule metadata alone may escalate action. |
| YARA-X | Share compiled `Rules`, create one `Scanner` per worker; record namespace, ID, tags, metadata, source digest, compile warnings/errors/ignored rules. R12a §§2, 5. [YARA-X Python API](https://virustotal.github.io/yara-x/docs/api/python/). | Forge hit: `STRONG` or `SUPPORTING`, final verdict at most suspicious until explicit rule promotion; module structure is context. | Set timeout and `max_matches_per_pattern`; `TimeoutError`/`ScanError` become typed failures. Whole-file scan by path needs generation checks; front/tail scanning is fixed partial and must not pretend offset or `filesize` semantics represent the original file. R12a §§2, 4, 6. |
| ClamAV | Verify private connected daemon identity, loaded DB inventory and active daily generation, config digest, reload state, and transport. Send bounded bytes by `INSTREAM`; current framing is `zINSTREAM\0`, 4-byte network-order chunk lengths, zero terminator (`agent/sentinel/engine/clamav.py:195-202`). [ClamAV protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html). | Exact reply name preserved. `PUA.*`, `Heuristics.*`, `BC.Heuristics.*`, reviewed weak names, limit/encrypted alerts are nonconclusive; other accepted names follow the owner’s default conclusive policy, subject to verified daemon/database provenance. R8c §§2, 4–5. | Outer bytes sent are exact coverage. The existing prefix cap is 400 MiB (`agent/sentinel/engine/clamav.py:38-39,310-316`); `OK` does not prove nested completeness. Wrong frame, missing NUL, overlong reply, timeout, stale/unverified daemon, or incomplete reload become typed nonclean states. |
| Defender | Applicable only when active and configured; current refresh TTL is 600 s, pathname custom scan timeout 90 s, `-DisableRemediation` (`agent/sentinel/engine/defender.py:25-30,73-85,107-120`). | Named threat with exit `2`: conclusive; exit `0`: completed negative only if same generation is verified before/after. Current parser uses this conservative `2` rule (`agent/sentinel/engine/defender.py:123-133`). | Exit `2` without name and other nonzero exits: `ERROR`; timeout: `TIMEOUT`; passive/not installed: typed applicability. Terminate a cancellable child through a Job Object, as locked in `PROJECT_CONTEXT.md` §10. |
| Structural analyzers | Bounded, non-executing PE/.NET/LNK and script/container metadata. YARA-X `pe`, `dotnet`, and `lnk` are the first parser candidates; preserve `module_not_run`, `parsed_false`, and `parsed_partial`. R12a §3. | Capability, signer declaration, command target, macro presence, entropy and package adjacency are supporting/context only. R10 §§3–6. | A malformed or opaque member is partial; no execution/import/evaluation of scanned content. A separate Windows trust check must distinguish valid, unsigned, invalid, revoked, unavailable, and offline revocation uncertainty. [Microsoft trust return values](https://learn.microsoft.com/en-us/windows/win32/seccrypto/certificate-and-trust-return-values). |
| capa, optional | Trusted isolated static-analysis child on eligible PE/.NET files after Gate v2 decision, pinned rules/version. R12b §§3–4. | Explanation document only: capability IDs, scopes, locations, limitations. | Hard parent deadline and memory cap; absence, error, or limitation never changes `FinalDecision`. |
| Smart-scan source collector | Watched folders; user/Common Startup; HKCU/HKLM Run/RunOnce in both views; readable Task Scheduler executable actions; process image paths. This is the locked scope (`PROJECT_CONTEXT.md` §10). R12c §5 details the Windows APIs and failure modes. | `SourceResult` records discovered target, source entry, resolved/unresolved status, and denied count; same file is deduped by handle identity. | Missing key is distinct from access denied; task folders must be enumerated through COM; no UNC, process memory, or elevation. [Microsoft alternate registry views](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view), [Task Scheduler folders](https://learn.microsoft.com/en-us/windows/desktop/api/taskschd/nf-taskschd-itaskfolder-getfolders). |

**Readiness detail for ClamAV.** The adapter exposes separate booleans/codes for `transport_ready`, `daemon_verified`, `database_loaded`, `database_verified`, `database_fresh`, `reload_confirmed`, and `configuration_acceptable`. A freshclam executable exit `1` is not its “up to date” process result; `RELOADING` is not activation. R8c §3. Current `update()` accepts `0` or `1` when files exist (`agent/sentinel/engine/clamav.py:127-148`), and `ready()` relies on a cached `PING` (`agent/sentinel/engine/clamav.py:255-265`). These checks must be replaced before an `OK` contributes trusted coverage.

## 6. Verdict and action policy

### Evidence classification, in precedence order

| Condition | Evidence category/strength | Final effect |
|---|---|---|
| Built-in EICAR SHA-256 or verified known-bad DB hash for this exact file | Malware / conclusive; EICAR has `is_test_file=true` | `malicious`; EICAR uses ordinary quarantine policy and is displayed as a test file. Current hash IDs are in `agent/sentinel/engine/signatures.py:21-22,69-77`. |
| Explicit, locally validated critical **user** rule pack | Malware / conclusive | `malicious` |
| Defender exit `2` plus nonempty parsed `Threat:` and same verified generation | Malware / conclusive | `malicious` (`agent/sentinel/engine/defender.py:123-133`) |
| Verified private clamd `FOUND` outside weak/coverage classes | Malware / conclusive under locked default | `malicious`; preserve name and DB provenance, without claiming its mechanism |
| `PUA.*`, `BC.Heuristics.*`, `Heuristics.*`, `Weak.*`, reviewed weak-name set including `Win.Trojan.Suspect-34` | PUA/heuristic or weak / supporting | At most `suspicious`; no evidence-v1 auto-quarantine. `PUA.Win.Exploit.*` stays weak by first-match precedence. |
| `Heuristics.Limits.Exceeded.*`, `Heuristics.Encrypted.*` | Coverage | `partial`/opaque coverage, not malware |
| One Forge match; PE packing/unsigned; deceptive filename; MotW/blocklisted origin; script capability; signer anomaly | Supporting/context | `suspicious` only when an explicit rule says so; otherwise retain as context |
| Multiple correlated weak hits from one source/ruleset | Same correlation group | Count once; never become conclusive by addition |
| Several independent strong but nonconclusive observations | Supporting | **Proposal:** `suspicious` pending owner-approved, FP-measured promotion rule; no arithmetic threshold |

`Generic`, `Gen`, and `Agent` are neither automatically weak nor proof of an exact hash. `Packed` and `Obfuscated` get no special name rule until false-positive measurement. These are locked in `PROJECT_CONTEXT.md` §11. A signed file cannot override an accepted malware hit; published research documents signed malware, while Windows signer verification itself is a distinct trust operation. [Certified Malware](https://users.umiacs.umd.edu/~tdumitra/papers/CCS-2017.pdf).

### Final decision table

Evaluate top to bottom. `accepted` means verified source, same file generation, valid contract, and policy-recognized signature.

| Priority | Condition | Verdict | `trusted_clean` | Reason |
|---:|---|---|---:|---|
| 1 | Accepted conclusive malware evidence, even if another stage is partial or failed | `malicious` | false | `CONCLUSIVE_LOCAL`, `CLAMAV_CONCLUSIVE`, or `DEFENDER_THREAT` |
| 2 | No conclusive evidence; accepted weak/PUA or an explicit suspicious correlation rule | `suspicious` | false | `WEAK_DETECTION`, `PUA_DETECTION`, `CORROBORATED_SIGNALS` |
| 3 | No accepted detection; any required applicable stage failed, timed out, was cancelled, changed, unverified, or has runtime partial/opaque coverage | `unknown` | false | exact stage and `INCOMPLETE_COVERAGE`, `ENGINE_TIMEOUT`, `CHANGED`, etc. |
| 4 | No detection; all applicable required stages completed on one generation, all required objects accounted for, full policy active | `clean` | true | `COMPLETE_NO_DETECTION` |
| 5 | Same as row 4 under intentionally disabled stages or fixed reduced coverage | `clean` **for reduced policy only** | false | `REDUCED_POLICY` or `FIXED_PARTIAL` |

A clamd `OK` on a simple ordinary file can satisfy its declared **outer-byte** stage if identity/readiness are verified. It cannot attest to every possible hidden or nested representation. A recognized container with unverified child accounting remains unknown unless independent inventory establishes the policy’s required object coverage. This is a proposed, testable interpretation of R8a–R8c, rather than a capability promised by clamd.

### Action table

| Policy / condition | Action | Reason code |
|---|---|---|
| `evidence-v1`, malicious from accepted conclusive evidence, auto-quarantine on, current protection generation, current file identity/hash verified | Quarantine | `AUTO_CONCLUSIVE` |
| Same, auto-quarantine off | Notify | `AUTO_DISABLED` |
| Suspicious or PUA only | Notify/review | `WEAK_ONLY` / `PUA_USER_CHOICE` |
| Unknown without accepted detection | Retry or report coverage debt | `INCOMPLETE_COVERAGE` |
| Unverified daemon detection without independent conclusive hit | Notify only | `UNVERIFIED_CLAMD` |
| File changed before action | No action; rescan | `CHANGED_BEFORE_ACTION` |
| Protection generation revoked | No action | `PROTECTION_STOPPED` |
| User path+hash restore exception matches current file | Suppress repeat automatic action, retain finding | `RESTORE_EXCEPTION` |
| Explicit Trust operation matches its separately approved scope | Suppress according to trust record, retain audit | `USER_TRUST` |

The locked default `legacy-v0` action mode preserves the old user-visible quarantine policy until `evidence-v1` is enabled (`PROJECT_CONTEXT.md` §7). **Proposal:** even in `legacy-v0`, the new identity, daemon verification, protection-generation, and action transaction guards remain mandatory. Legacy score or name behavior is recorded with `action_policy_version="legacy-v0"` so it can be measured and retired; it must never manufacture trusted clean.

CLI aggregate precedence remains **malicious `2` > operational/incomplete failure `3` > suspicious `1` > clean `0`** (`PROJECT_CONTEXT.md` §11; current implementation `agent/sentinel/__main__.py:67-74`). A deterministic fixed partial scan is shown as partial but is not automatically exit `3`; runtime failure, changed file, unreadable source, or engine failure is.

## 7. Test plan and release criteria

All fixtures are harmless synthetic bytes or locally installed legitimate software. Do not write EICAR to disk; the current built-in EICAR case can be exercised from in-memory bytes (`agent/sentinel/engine/signatures.py:21-22,69-71`; `PROJECT_CONTEXT.md` §12).

| Layer | Required tests | Acceptance condition |
|---|---|---|
| Contract/validation | Round-trip every enum and schema version; reject malformed ranges, negative times, mismatched identity, duplicate engines, unknown version. | Invalid data cannot become clean or authorize action. |
| Verdict table | Cartesian cases for completed/partial/skipped/unavailable/error/timeout/cancelled/unverified/changed × no hit/weak/conclusive; conflicting engine results; PUA and EICAR. | Exact table above; no score-based promotion. |
| Identity | Benign A/B same-size swap with restored mtime between each stage; path alias, hard link, rename, reparse/long Unicode path; changed-after-Defender. | Combined clean and action denied on mismatch; one scan-local file ID per generation. |
| Core/container | Synthetic ZIP with encrypted metadata, unsupported method, malformed directory, 2,001 entries, depth four, oversize member and expansion budget; parser raises injected exceptions. | Every omitted object has a reason; no empty-result-to-clean conversion. |
| Rules/YARA-X | Test-only duplicate identifiers in different namespaces; compile partial success, warnings, ignored rule; timeout, scan error, match cap, front/tail offset and `filesize` rule. | Rule manifest/digest stable; timeout and degraded load not clean; namespace retained. |
| Fake clamd | Strict protocol frame cases: `OK`, `FOUND`, `ERROR`, empty, wrong prefix, EOF before NUL, overlong, limit/encrypted names, `BC.Heuristics.*`, unknown name, wrong daemon, old version after `RELOADING`. | All statuses and strengths match the adapter table; unverified `FOUND` is notify-only. |
| Real clamd | Optional, isolated private daemon and temporary `SENTINEL_HOME`; harmless clean file and in-memory EICAR; synthetic nested benign containers; reload confirmation with a harmless test-only rule where safe. | No real daemon is assumed in CI; skipped tests are reported as skips, not passes. The project previously had three real-clamd tests that skip when no daemon runs (`PROJECT_CONTEXT.md` §5). |
| Defender | Inject runner for exit `0`, exit `2` with/without name, other exit, timeout and OSError; A/B path-generation swap. | Only named `2` is conclusive; no failure becomes clean. |
| Action/quarantine | Pause between decision and claim; replace file; revoke protection generation; inject DB/copy/delete errors; restore under occupied original path. | No wrong-generation quarantine; complete or rollback; restore adds path+hash only. |
| Concurrency/cancel | Two and four file workers, per-file sequential order, YARA scanner per worker, ClamAV pool cap, Defender single slot; cancel during hash, ZIP, INSTREAM and Defender. | No cross-file result mixing; cancelled not cached; accepted detection reaches an action decision. |
| Events | 500,000 progress events with paused consumer; high terminal-event burst; sequence gaps, duplicate IDs, privacy schema. | Bounded resident memory, nonblocking worker publication, terminal detection/error/action events durable and ordered. |
| Smart-scan scope | Inject each source, missing/denied registry views, task folder denial, unreadable Startup link, vanished process, duplicate hard links, Sentinel data path. | Source-entry coverage debt visible; one file scan per identity; Sentinel data excluded before queueing. |
| FP corpus | Frozen local clean-software manifest: Windows components, installers, games/anti-cheat, admin/developer tools, portable apps, archives, scripts, browser extension metadata. Run read-only with disposable `SENTINEL_HOME`, auto-quarantine off, at baseline and candidate. | Report per-file and per-device false alerts, unknown/partial rates, version digest, and category breakdown. Owner approves numerical alert budget before release. |
| Performance | Harmless synthetic sizes around every limit, repetitive rule-match input, archive metadata load, slow/locked file, many source entries. | **Provisional proposal:** two workers default/four maximum, 256 MiB weighted in-flight resident budget, explicit per-file deadline (60 s real-time, 120 s deep), no unbounded parser/match/event allocation. Budget exceedance is typed incomplete. Final numbers require owner-machine measurement. |

R7’s evaluation guidance calls for temporal/source separation and low-FPR reporting; feature-only external datasets may inform later model work, but this implementation gate needs no executable samples. `docs/handoff/codex-literature-r7.md` “Evaluation methodology”; [TESSERACT](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury).

## 8. Ordered implementation milestones

Each milestone is a reviewable change group. File lists are **proposed paths**, not files created in this round. Claude must review the diff and run the relevant tests before merge, as required by `AGENTS.md`.

| Milestone | Files created/changed | Claude’s merge check |
|---:|---|---|
| 1. Schema and pure policy | New `gate_v2/contract.py`, `coverage.py`, `policy.py`; new focused tests under `tests/codex/` in Codex writing rounds | Validate serialization, reason-code table, invariant tests, version rejection; inspect that no legacy score controls policy. |
| 2. File identity and orchestrator skeleton | New `gate_v2/identity.py`, `orchestrator.py`, `events.py`; adapter shell in `engine/scanner.py` | A/B swap and cancellation tests; Windows handle identity, long-path, and event bounds on owner machine. |
| 3. Core and rule adapters | New `gate_v2/core.py`, `rules.py`; existing `engine/signatures.py`/`yarafeed.py` integration | Synthetic ZIP/PE/rule corpus, compile diagnostics, per-worker YARA scanners, ruleset digest, memory/time results. |
| 4. ClamAV adapter | New `gate_v2/clamd.py`; update `engine/clamav.py` integration | Fake protocol matrix, private daemon identity, active DB/reload verification, optional real clamd run; confirm no `OK` overclaim. |
| 5. Defender and structural context | New `gate_v2/defender.py`, `analyzers/` modules | Runner return-code matrix; same-generation path check; benign LNK/script/document/PE fixtures; signer state distinct from certificate-table presence. |
| 6. Cache and legacy adapter | New `gate_v2/cache.py`, `legacy.py`; update `engine/scanner.py`, `db.py` | Existing caller compatibility, same-count rule swap invalidation, partial/unavailable cache rules, additive serialized `scan_result`. |
| 7. Actions and callers | New `gate_v2/actions.py`; update `protection.py`, `quarantine.py`, `scanjob.py`, `watcher.py`, `nativehost.py`, CLI/tray UI | Transaction and stop-barrier tests; Restore path+hash; CLI precedence; native response compatibility; Vietnamese user text. |
| 8. Smart/deep scope and release measurement | New `gate_v2/scope.py`; update scan UI/CLI and reports; FP manifest/report tests | Every locked source and denied-entry count, deep-scan scope/budgets, pipeline event display, baseline-versus-candidate FP and performance report. |

Before each merge Claude should run `tools/check_codex_scope.ps1 -Base <start commit> -Allow <task paths>`, inspect every changed line, record acceptance/rejection in `REVIEWS.md`, and run the required Python and extension suites. Those are repository process requirements stated in `AGENTS.md`; no such check or test was run in this read-only round.

## 9. Open decisions for the owner

| Decision | Proposed default | What would settle it |
|---|---|---|
| When to switch `legacy-v0` auto-quarantine to `evidence-v1` | Ship Gate v2 with versioned legacy behavior, collect FP results, then explicitly switch. | Owner approval after the frozen clean-corpus report; `PROJECT_CONTEXT.md` §7 locks legacy default for now. |
| Exact trusted-clean policy when ClamAV is uninstalled/passive Defender is unavailable | Full-policy trusted clean requires the configured required stages; reduced-policy clean is visibly untrusted. | Decide which engines are required for each product mode and UI claim. |
| Clamd ownership check | Prefer verifying the connected socket’s owner PID against the launched process identity; retain listener PID/creation time/image/file ID checks. | Windows integration test on the owner’s setup; `PROJECT_CONTEXT.md` §11 leaves listener versus socket-tuple versus broker open. |
| ClamAV opaque-container treatment | Mark known opaque/unsupported children incomplete; do not treat ordinary `OK` as proof of all recursive work. | Harmless format/variant fixture matrix and a decision about which independent parser inventory is mandatory for trusted clean. |
| Trust action scope and expiry | Restore path+hash only; separate Trust defaults to explicit path+hash with an expiry and audit record. | Owner choice of broader trust scopes and UI wording. |
| Numerical budgets | Use the provisional worker/memory/deadline values in §7 only as measurement targets. | Benign owner-machine latency and peak-memory results, including slow disks and large installers. |
| False-positive release budget | Freeze a clean corpus and fail any regression in automatic quarantine; report alert/unknown rates separately. | Owner-selected allowed count per device and acceptable abstention rate. |
| Deep scan’s added analyzers | Start with broader scope, longer limits, and deferred optional explanation; never lower detection thresholds. | Owner review of elapsed time, memory and FP report against smart scan. |
| Optional PE ML and broader package analyzers from R7/R10 | Keep out of the first trusted-clean/action gate; add as suspicious/context only after validation. | Feature-only temporal evaluation and local clean-corpus FP measurement. |

The main implementation risk is semantic overclaim: a completed engine call is narrower than complete inspection of a complex file. Gate v2’s contract must preserve that distinction all the way through cache, UI, CLI exit code, and quarantine.