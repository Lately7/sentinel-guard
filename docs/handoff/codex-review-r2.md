# Codex design review — round 2 (read-only, session 01a19b4d-b7b0-7240-a851-dbd9aab366ce)

## Question sent by Claude

## Design discussion, round 2: direction and method (read-only)

Still read-only: do NOT modify, create or delete any file. Thank you for round 1;
Claude checked your main claims against the code and they hold (Defender
error/timeout reported as clean, rule-count-only cache key, `skipped` cleared on
oversized ZIP, the two tests locking rejected decisions, the AGENTS.md conflict).

### Decisions the project owner locked after round 1

Where Claude and you disagreed, the owner chose:

1. ClamAV names not on any list: auto-quarantine by DEFAULT, with a DENYLIST of
   weak name patterns that only notify (`Suspect`, `Heuristics.`, `PUA.`,
   `Phishing`, ...). Reason: ClamAV has millions of names, an allowlist cannot be
   reviewed; Defender is passive on this machine so ClamAV is the main line;
   quarantine is reversible.
2. A single YARA Forge match stays SUSPICIOUS. "One signature hit is enough for
   malicious" covers: known-bad hash, ClamAV (minus the denylist), user rule
   packs with severity critical, Defender.
3. False-positive measurement: Claude also runs a READ-ONLY scan of legitimate
   software already on the machine (System32, Program Files) — "synthetic only"
   applies to positive (malicious) samples. Your synthetic manifest corpus is
   used in parallel for regression.
4. Commit the current gate as-is as baseline, then fix the 3 serious defects in a
   separate commit BEFORE Codex round 1.

Planned commit sequence (each on a new branch, user reviews each diff):
- C1: pre-existing icon / TASKS.md changes (not part of the gate work).
- C2: multi-layer gate as-is + `docs/baseline.md` with real test results
  (pytest + node, with and without a running clamd; pass/skip counts).
- C3: fix Defender-error-as-clean, cache key (content digests), `skipped` on
  oversized ZIP; revise `tests/test_agent.py:31` and `tests/test_gate.py:109`;
  update AGENTS.md for Codex's new role (writes only `tests/codex/` and
  `reports/red-team.md`); add `tools/check_codex_scope.ps1`; record decisions in
  REVIEWS.md and the other 7 defects as known issues RT-xxx.
- C4: `CODEX_TASK.md` for round 1 (characterization tests), pinned to C3's hash;
  then run Codex with `--sandbox workspace-write`.
- Later: Scanner Contract v1 (Claude), regression review (Codex), quarantine
  hardening incl. `should_auto_quarantine()`, Restore vs Trust, data-dir
  exclusion (Claude + Codex).

### What we want from you now: method, not re-litigation

A. Critique the commit sequence. Anything in the wrong order, missing, or too
   big for one reviewable commit? Should any of the 7 minor defects move into C3?

B. Concrete design proposals, each with a short code sketch (signatures/types
   only, no full implementation) and the file it belongs in:
   1. The ClamAV weak-name denylist: exact patterns you would start with, how it
      is versioned/configured, and how to keep it testable when the ClamAV DB
      renames signatures.
   2. `should_auto_quarantine(verdict, policy) -> Decision` — inputs, the
      decision record it returns (reason codes), and how it composes with the
      current `act_on()` so behaviour is unchanged until the policy is switched on.
   3. The cache key: what goes in the "gate digest" (rule file digests, ClamAV
      daily/main versions, Defender state, settings), when results must NOT be
      cached (any engine error/unavailable/partial?), and how to avoid the 60 s
      version-cache staleness after a clamd RELOAD.
   4. Scanner Contract v1 data shape: a JSON example for one file with ClamAV
      detected, YARA partial, Defender unavailable; and the backward-compatible
      mapping to today's `Verdict.to_dict()` and native-host `scan_download`
      response that the extension reads.
   5. Defender status: how to distinguish clean / threat / error / timeout from
      `MpCmdRun.exe` output and exit codes, given exit code 2 is shared by
      "threat found" and "scan failed" (see `engine/defender.py`).

C. Round 1 plan for yourself: the list of test files you would create under
   `tests/codex/`, the main test cases in each (names only), which ones are
   expected to be `xfail(strict=True)` known issues with their RT ids, and what
   you need from Claude beforehand (fixtures, transport injection hooks for the
   ClamAV client so most tests need no socket, a fake Defender runner, etc.).

D. The `CODEX_TASK.md` skeleton you would want to receive: section headings and
   the exact acceptance criteria for "round 1 passed".

E. Risks you see in this whole approach that nobody has raised yet.

Answer in English, sections A–E, concise, cite file:line where relevant. Do not
claim to have run anything you did not run.

## Codex answer (verbatim)

## A. Commit sequence

The direction is sound, but C2 and C3 are too broad for clean review and audit.

### Recommended sequence

1. **C1 — unrelated assets/metadata**
   - Icons and genuinely pre-existing `TASKS.md` changes only.
   - Ensure `TASKS.md` does not quietly introduce gate acceptance criteria into an “unrelated” commit.

2. **C2a — baseline gate code**
   - Gate implementation and its existing tests, unchanged.
   - Explicitly mark the commit/branch non-release because it contains known auto-quarantine defects.

3. **C2b — baseline evidence**
   - `docs/baseline.md` only.
   - Reference C2a’s exact commit hash, ClamAV engine/database version, commands, environment, pass/skip counts, and whether clamd was running.
   - This avoids the circular problem of recording a commit hash inside the same commit whose hash changes when the document is added.

4. **C3a — Defender result correctness**
   - Typed clean/threat/error/timeout result plus regression tests. The current empty-list API conflates all four states ([defender.py:64](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/defender.py:64)).

5. **C3b — cache identity and cacheability**
   - Content-based gate digest.
   - No caching of transient incomplete results.
   - ClamAV reload invalidation.
   - Tests for same-count rule replacement and engine recovery.

6. **C3c — oversized coverage preservation**
   - Do not clear `skipped` at [scanner.py:109](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:109).
   - Replace hard-coded “64 MB” coverage text at [scanner.py:208](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:208) while touching the same path.
   - Regression tests.

7. **C3d — governance**
   - Revised rejected tests.
   - `AGENTS.md`, scope checker, `REVIEWS.md`, and canonical RT registry.
   - Test the scope checker before pinning C4. Keeping it outside Codex’s allowed paths makes it immutable during the Codex round.

8. **C4 — task specification**
   - Pin the final C3d commit and scope-script digest.
   - Start from a clean worktree.

### Minor defects to move forward

Move only two:

- The hard-coded coverage text belongs with C3c.
- Native-host exact-read handling is a small trust-boundary fix worth a separate C3e before characterization; currently the body is read once at [nativehost.py:194](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/nativehost.py:194).

Keep the following deferred because they require policy or architectural work: cross-layer TOCTOU, watcher/data-directory exclusion, `scan_bytes()` layer consistency, Restore versus Trust, and contradictory per-layer status. Do not opportunistically mix them into the three correctness commits.

## B. Concrete designs

### B1. ClamAV weak-name policy

Put the pure classifier in a new `agent/sentinel/engine/clamav_policy.py`. Keep it separate from socket/process management in `clamav.py`.

```python
@dataclass(frozen=True)
class WeakNameRule:
    id: str
    pattern: Pattern[str]

@dataclass(frozen=True)
class ClamNameClassification:
    weak: bool
    rule_id: str | None
    policy_version: str

CLAMAV_NAME_POLICY_VERSION = "1"

def classify_clamav_name(
    name: str,
    *,
    extra_globs: tuple[str, ...] = (),
) -> ClamNameClassification: ...
```

Initial case-insensitive, ASCII patterns:

```python
r"^Heuristics\."
r"^(?:PUA|PUP|Adware|Riskware|HackTool|Tool|Joke)\."
r"(?:^|[._:-])Suspect(?:[._:-]|$)"
r"(?:^|[._:-])Phishing(?:[._:-]|$)"
r"(?:^|[._:-])(?:Encrypted|ContainsMacros|Broken)(?:[._:-]|$)"
r"(?:^|[._:-])Limits[._-]Exceeded(?:[._:-]|$)"
```

This catches `Win.Trojan.Suspect-34` without downgrading all `Win.Trojan.*`. Current code recognizes only two prefixes ([clamav.py:228](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/clamav.py:228)).

Configuration:

- Built-in rules are code-owned and cannot be removed through ordinary settings.
- Permit only additive, length/count-bounded case-insensitive globs in settings, not arbitrary regexes.
- Effective version: `built_in_version + SHA256(canonical additional globs)`.
- Record `policy_version` and matched rule ID in findings/events.

Database rename resilience:

- Test semantic tokens, not exact full signature names.
- Maintain a versioned calibration fixture of observed strong and weak names.
- Record the actual ClamAV name and DB version in measurement results.
- If a formerly weak corpus sample receives a renamed name that no longer matches, fail the calibration test and review the pattern. There is no reliable way to infer metadata provenance from INSTREAM’s name-only reply ([clamav.py:217](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/clamav.py:217)).

Also add a structured `signature_id` field to the future finding contract. Do not make quarantine policy parse `"ClamAV: ..."` from `detail`.

### B2. `should_auto_quarantine`

Put the policy types and pure decision function in a new `agent/sentinel/quarantine_policy.py`; integrate them in `protection.py`.

```python
class QuarantineAction(StrEnum):
    QUARANTINE = "quarantine"
    NOTIFY_ONLY = "notify_only"
    NONE = "none"

class DecisionReason(StrEnum):
    LEGACY_MALICIOUS = "legacy_malicious"
    POLICY_DISABLED = "policy_disabled"
    NOT_MALICIOUS = "not_malicious"
    NO_PATH = "no_path"
    KNOWN_BAD_HASH = "known_bad_hash"
    CLAMAV_STRONG = "clamav_strong"
    CLAMAV_WEAK_NAME = "clamav_weak_name"
    USER_CRITICAL_RULE = "user_critical_rule"
    DEFENDER_THREAT = "defender_threat"
    HEURISTIC_ONLY = "heuristic_only"

@dataclass(frozen=True)
class QuarantinePolicy:
    version: str
    mode: Literal["legacy-v0", "evidence-v1"]
    clamav_name_policy_version: str

@dataclass(frozen=True)
class Decision:
    action: QuarantineAction
    reason: DecisionReason
    policy_version: str
    engine: str | None = None
    finding_rule: str | None = None
    signature_id: str | None = None

def should_auto_quarantine(
    verdict: Verdict,
    policy: QuarantinePolicy,
) -> Decision: ...
```

Backward-compatible composition:

```python
def act_on(
    db: Database,
    verdict: Verdict,
    settings: Settings,
    source: str,
    *,
    quarantine_policy: QuarantinePolicy | None = None,
) -> dict[str, Any]: ...
```

`None` must preserve today’s exact behavior: malicious plus `settings.auto_quarantine` quarantines ([protection.py:23](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/protection.py:23)). Only entry points explicitly passing `evidence-v1` switch behavior.

Return the decision additively in the outcome and store it with the event. The settings flag remains the master kill switch; policy decides eligibility.

### B3. Cache key

Add immutable identity types, preferably in `engine/scanner.py` initially and later move them with Contract v1.

```python
@dataclass(frozen=True)
class RuleManifest:
    digest: str
    files: tuple[tuple[str, str], ...]  # namespace/name, SHA-256

@dataclass(frozen=True)
class ClamDatabaseIdentity:
    engine_version: str
    main_version: str | None
    daily_version: str | None
    manifest_digest: str
    reload_generation: int

@dataclass(frozen=True)
class GateIdentity:
    scanner_cache_schema: int
    app_version: str
    rule_manifest: RuleManifest
    clamav: ClamDatabaseIdentity | None
    defender_active: bool
    defender_engine_version: str | None
    defender_db_version: str | None
    settings_digest: str
    limits_digest: str

    def digest(self) -> str: ...

def is_cacheable(result: ScanResult) -> bool: ...
```

Include:

- Rule filename/namespace and raw file SHA-256, sorted deterministically. Filename matters because YARA namespaces use `f.stem`.
- YARA-X version and the loaded-rule manifest.
- Application/scanner cache-schema version.
- Bad-hash database generation.
- ClamAV engine, main, daily and bytecode/database manifest identity.
- Defender active state, engine version and signature version.
- Enabled-engine flags.
- Deep-scan/archive limits and detection thresholds.
- Any detection setting that can alter results.

Do not include quarantine policy if it is re-evaluated from structured cached findings. Include it only if action decisions themselves are cached.

Conservative C3 cacheability:

- Never cache unreadable/changed results.
- Never cache any result containing `error`, `timeout`, or transient `unavailable`.
- Never cache partial results initially.
- A user-disabled engine is `skipped_by_policy`, not unavailable, and may be cached because the setting is in the digest.
- Malicious detections may later be cached even when another layer is incomplete, but that optimization should wait for Contract v1.

The current gate identity uses only rule counts and a cached ClamAV version ([scanner.py:50](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:50)).

For ClamAV reload:

```python
class ClamAVEngine:
    def database_identity(self, *, refresh: bool = False) -> ClamDatabaseIdentity: ...
    def reload_database(self, timeout: float = 30.0) -> ClamDatabaseIdentity: ...
    def invalidate_database_identity(self) -> None: ...
```

After successful freshclam/RELOAD:

1. Invalidate `_version`.
2. Poll `VERSION` until the expected identity is visible.
3. Atomically publish a small database-manifest/reload-generation file.
4. Make every engine instance include that generation in its digest.

Do not rely on the current 60-second cache at [clamav.py:318](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/clamav.py:318). Hash large database files only during update; ordinary scans should validate a small manifest against filename/size/mtime/header metadata.

### B4. Scanner Contract v1

Put types in a new `agent/sentinel/engine/contract.py`; retain the legacy adapter in `verdict.py`.

```python
EngineStatus = Literal["completed", "partial", "skipped", "unavailable", "error", "timeout"]
EngineVerdict = Literal["clean", "suspicious", "malicious", "unknown"]

@dataclass(frozen=True)
class Coverage:
    kind: Literal["full", "ranges", "metadata_only", "none"]
    ranges: tuple[tuple[int, int], ...] = ()
    reason: str | None = None

@dataclass(frozen=True)
class EngineResult: ...

@dataclass(frozen=True)
class ScanResult:
    def to_contract_dict(self) -> dict[str, Any]: ...
    def to_legacy_verdict(self, max_findings: int = 200) -> dict[str, Any]: ...
```

Example for a file between 64 MB and 400 MB:

```json
{
  "contract_version": 1,
  "name": "sample.zip",
  "path": "C:\\Downloads\\sample.zip",
  "sha256": "8c…",
  "size": 104857600,
  "duration_ms": 842,
  "verdict": "malicious",
  "trusted_clean": false,
  "findings": [
    {
      "engine": "clamav",
      "rule": "clamav.detection",
      "signature_id": "Win.Trojan.Agent-123",
      "severity": "CRITICAL",
      "detail": "ClamAV: Win.Trojan.Agent-123",
      "score": 100
    }
  ],
  "engines": {
    "sentinel": {
      "contract_version": 1,
      "status": "completed",
      "verdict": "clean",
      "findings": [],
      "engine_version": "0.1.0",
      "db_version": "bad-hashes:42",
      "coverage": {
        "kind": "metadata_only",
        "ranges": [[0, 65536]],
        "reason": "full-file hash plus name/header checks"
      },
      "sha256": "8c…",
      "size": 104857600,
      "duration_ms": 120,
      "error": null
    },
    "rules+yara": {
      "contract_version": 1,
      "status": "partial",
      "verdict": "unknown",
      "findings": [],
      "engine_version": "yara-x:1.x",
      "db_version": "sha256:rules…",
      "coverage": {
        "kind": "ranges",
        "ranges": [[0, 67108864], [96468992, 104857600]],
        "reason": "size_limit"
      },
      "sha256": "8c…",
      "size": 104857600,
      "duration_ms": 330,
      "error": null
    },
    "clamav": {
      "contract_version": 1,
      "status": "completed",
      "verdict": "malicious",
      "findings": [
        {
          "rule": "clamav.detection",
          "signature_id": "Win.Trojan.Agent-123",
          "severity": "CRITICAL",
          "detail": "ClamAV: Win.Trojan.Agent-123",
          "score": 100
        }
      ],
      "engine_version": "ClamAV 1.5.4",
      "db_version": "main:62,daily:28172",
      "coverage": {"kind": "full", "ranges": [[0, 104857600]]},
      "sha256": "8c…",
      "size": 104857600,
      "duration_ms": 392,
      "error": null
    },
    "defender": {
      "contract_version": 1,
      "status": "unavailable",
      "verdict": "unknown",
      "findings": [],
      "engine_version": null,
      "db_version": null,
      "coverage": {"kind": "none", "ranges": []},
      "sha256": "8c…",
      "size": 104857600,
      "duration_ms": 0,
      "error": {
        "code": "not_active",
        "message": "Defender is not the active antivirus"
      }
    }
  },
  "error": null
}
```

Backward compatibility:

- Keep today’s `Verdict.to_dict()` keys and meanings at [verdict.py:74](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/verdict.py:74).
- Derive the legacy `engines` strings from `EngineResult`.
- Never clear legacy `skipped` while any required layer is partial.
- For a partial no-hit result, the contract says `unknown`; the temporary legacy adapter may still say `label: clean` plus `skipped`.
- Add a sibling `scan_result` field to the native response rather than replacing `verdict`:

```python
{
    "verdict": result.to_legacy_verdict(max_findings=30),
    "scan_result": result.to_contract_dict(),
    "reason": ...,
    "url_reputation": ...,
    **outcome,
}
```

The extension only reads `res.verdict.label`, `score`, `reason`, and `quarantined` ([background.js:252](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/extension/src/background.js:252)), so this is additive.

Cap findings independently in both representations and expose `findings_total`; otherwise duplicating per-engine and aggregate findings risks the 1 MB native-message limit.

### B5. Defender result

Replace the list-only return with a typed result in `engine/defender.py`.

```python
@dataclass(frozen=True)
class DefenderResult:
    status: Literal["completed", "unavailable", "error", "timeout"]
    verdict: Literal["clean", "malicious", "unknown"]
    findings: tuple[Finding, ...]
    exit_code: int | None
    error_code: str | None
    error: str | None
    duration_ms: int

Runner = Callable[[Sequence[str], float], subprocess.CompletedProcess[str]]

def scan(
    path: str,
    timeout: float = 90.0,
    *,
    runner: Runner = run_mpcmd,
) -> DefenderResult: ...

def parse_result(
    returncode: int,
    stdout: str,
    stderr: str,
) -> DefenderResult: ...
```

Classification:

- Named `Threat:` lines: malicious. If the exit code is unexpected, preserve the detection but set status/error metadata accordingly.
- Exit 0 with no named threat: completed/clean.
- Exit 2 with no named threat: error/unknown.
- Any other nonzero exit: error/unknown.
- `TimeoutExpired`: timeout/unknown.
- `OSError`: error/unknown with `start_failed`.
- Missing file or inactive Defender: unavailable/unknown, not clean.

Parse bounded stdout and stderr together. The important rule remains that exit code 2 alone is never evidence; current parsing already recognizes that ambiguity but throws away the error state ([defender.py:76](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/defender.py:76)).

## C. Codex round 1 plan

C3 should first assign canonical IDs. Suggested mapping below:

- RT-001: evidence-based auto-quarantine/Clam weak-name policy absent
- RT-002: Restore creates global hash trust
- RT-003: watcher does not exclude Sentinel data
- RT-004: partial scans can appear clean
- RT-005: cross-layer TOCTOU/mixed-byte verdict
- RT-006: native-host short body read
- RT-007: CLI/on-demand self-data exclusion and incomplete-result semantics

### Files under `tests/codex/`

`test_gate_characterization.py`

- `test_legacy_verdict_dict_shape`
- `test_engine_statuses_present_for_disk_scan`
- `test_partial_ranges_front_and_tail`
- `test_oversized_zip_preserves_incomplete_reason`
- `test_clam_detection_overrides_partial_coverage`
- `test_scan_bytes_layer_shape_is_documented`
- `test_partial_no_hit_is_not_trusted_clean` — xfail RT-004

`test_cache_contract.py`

- `test_same_count_pattern_rule_replacement_changes_gate_digest`
- `test_same_count_yara_replacement_changes_gate_digest`
- `test_clam_database_generation_changes_gate_digest`
- `test_defender_state_changes_gate_digest`
- `test_error_result_is_not_cached`
- `test_unavailable_result_is_not_cached`
- `test_partial_result_is_not_cached`
- `test_cached_result_requires_same_sha256`

`test_defender_contract.py`

- `test_exit_zero_is_clean`
- `test_exit_two_with_named_threat_is_malicious`
- `test_exit_two_without_threat_is_error`
- `test_nonzero_unexpected_exit_is_error`
- `test_timeout_is_timeout_not_clean`
- `test_start_failure_is_error_not_clean`
- `test_named_threat_is_preserved_with_unexpected_exit`

`test_clamav_name_policy.py`

- `test_heuristics_name_is_weak`
- `test_pua_and_pup_names_are_weak`
- `test_suspect_token_is_weak`
- `test_phishing_token_is_weak`
- `test_metadata_limit_names_are_weak`
- `test_known_strong_name_is_not_weak`
- `test_unknown_name_defaults_strong`
- `test_win_trojan_suspect_only_notifies` — xfail RT-001
- `test_policy_version_changes_with_additive_globs` — xfail RT-001

`test_nativehost_contract.py`

- `test_all_seven_message_types_validate_inputs`
- `test_message_ids_are_preserved`
- `test_oversized_input_is_drained_in_chunks`
- `test_oversized_output_becomes_bounded_error`
- `test_truncated_header_returns_eof`
- `test_short_body_reads_until_complete` — xfail RT-006 unless fixed in C3e
- `test_scan_download_legacy_response_shape`

`test_cli_contract.py`

- `test_exit_zero_clean`
- `test_exit_one_suspicious`
- `test_exit_two_malicious`
- `test_exit_three_unreadable`
- `test_json_stdout_is_valid`
- `test_diagnostics_stay_on_stderr`
- `test_mixed_detection_and_unreadable_precedence`
- `test_cli_walk_excludes_sentinel_data` — xfail RT-007

`test_quarantine_characterization.py`

- `test_quarantine_orders_claim_copy_record_delete`
- `test_hash_mismatch_rolls_back`
- `test_database_failure_restores_claim`
- `test_delete_failure_removes_database_record`
- `test_restore_never_overwrites`
- `test_restore_creates_path_hash_exception_only` — xfail RT-002
- `test_explicit_trust_is_separate_from_restore` — xfail RT-002
- `test_heuristic_only_malicious_does_not_auto_quarantine` — xfail RT-001

`test_watcher_characterization.py`

- `test_claim_files_are_ignored`
- `test_partial_suffix_uses_long_settle`
- `test_new_event_pushes_due_time_back`
- `test_rename_submits_destination`
- `test_changed_file_is_resubmitted`
- `test_data_directory_is_excluded`
- `test_data_directory_prefix_collision_is_not_excluded`
- `test_data_directory_case_and_realpath_variants_are_excluded`

The last three are xfail RT-003 until hardening.

`test_scan_races.py`

- `test_change_during_initial_read_is_incomplete`
- `test_change_during_clam_stream_is_incomplete`
- `test_change_before_defender_is_incomplete`
- `test_same_size_restored_mtime_replacement_is_detected` — xfail RT-005

`test_hostile_inputs.py`

- `test_malformed_zip_corpus_never_raises`
- `test_malformed_zip64_directory_never_raises`
- `test_malformed_pe_corpus_never_raises`
- `test_odd_filename_corpus_never_raises`
- `test_native_message_corpus_never_raises`

### Prerequisites from Claude

- Final C3 hash and canonical RT registry.
- A `ClamdClient` protocol injected into `ClamAVEngine`; most tests must not bind localhost. The current fake server requires a socket ([test_gate.py:27](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/tests/test_gate.py:27)).
- Defender runner injection as shown above.
- Clock/sleeper injection or a due-time method accepting `now` for deterministic watcher tests.
- Public, side-effect-free gate identity/cacheability helpers.
- Isolated temp-home fixture and harmless marker remain available.
- Defined CLI precedence for “unreadable plus malicious”; do not make Codex guess it.
- If Hypothesis is required, add it before C4; it is not currently in dev dependencies ([pyproject.toml:12](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/pyproject.toml:12)).
- Scope checker must reject symlinks/reparse points and verify a clean post-test `git status`, not merely inspect committed paths.

## D. Desired `CODEX_TASK.md`

### Required headings

1. Objective
2. Pinned Baseline
3. Authority and Allowed Paths
4. Locked Product Decisions
5. Current Public Interfaces
6. Known-Issue Registry
7. Required Characterization Matrix
8. Required Fixtures and Test Hooks
9. Commands and Environment
10. Localhost/External-Engine Procedure
11. Deliverables
12. Acceptance Criteria
13. Stop Conditions

### Exact acceptance criteria

Round 1 passes only when:

1. Work begins from the exact clean C3 commit named in the task.
2. The supplied scope script and its recorded SHA-256 match C3.
3. The only final changes are:
   - `tests/codex/**`
   - `reports/red-team.md`
4. No production source, existing test, configuration, dependency, fixture outside `tests/codex/`, generated artifact, symlink, reparse point, or alternate data stream is added or changed.
5. `tools/check_codex_scope.ps1 -Base <C3_HASH>` exits 0 both before reporting and after all tests.
6. The full Python suite exits 0.
7. `tests/codex/` exits 0 independently.
8. `node --test extension/test/` exits 0.
9. There are no XPASS results and every xfail is `strict=True` with one canonical RT ID.
10. There are no unexpected skips. The task contains an explicit allowlist for platform/real-engine skips.
11. Sandbox-safe ClamAV tests use injected transport and require no socket.
12. The localhost protocol integration suite is run by Claude outside the restricted sandbox; its exact command and result are recorded. A sandbox skip is not reported as a pass.
13. No network access, live user database, live quarantine directory, production settings, or real remediation is used.
14. EICAR is never written to disk; disk tests use only the harmless test marker.
15. Every report finding has: ID, severity, code evidence, test evidence, and status of fixed/rejected/deferred with rationale.
16. Test results in the report are generated from the final diff, not an earlier iteration.
17. `git status --short` after testing contains only the allowed deliverables.
18. No pass claim is made for any command not actually run.

Stop and report instead of proceeding if the pinned commit, hooks, RT registry, scope tool, or CLI precedence is missing or differs from the task.

## E. Additional risks

- **“Reversible quarantine” has limits.** Restoration may not preserve ACLs, alternate data streams, EFS state, sparse layout, cloud-placeholder state, timestamps, or hard-link topology. Quarantining a system file can still cause immediate outage even if bytes are recoverable.
- **Default-strong unknown ClamAV names amplify database drift.** A renamed weak signature becomes auto-quarantine eligible until calibration catches it. Record name and DB identity for every action.
- **The live legitimate-software corpus is not stable.** Windows and application updates change files between runs. Record path, SHA-256, size, signer if available, unreadable count, and OS build; otherwise FP-rate changes are not comparable.
- **A “read-only scan” still mutates Sentinel state.** `scan_file()` stores cache entries even when cache lookup is disabled ([scanner.py:144](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/engine/scanner.py:144)). Run System32/Program Files measurement with a disposable `SENTINEL_HOME`, auto-quarantine disabled, and Defender remediation disabled.
- **Baseline C2 is hazardous if accidentally deployed.** Protect or clearly label its branch; C2 contains known automatic-action defects by design.
- **Path-only scope checks are bypassable operationally.** Tests can temporarily modify production files and restore them before the final diff. Use read-only ACL/sandbox rules for production paths where possible and inspect status before and after each command.
- **Contract duplication can exceed native-message limits.** Aggregate plus per-engine findings must be capped and counted; `scan_download` currently caps legacy findings at 30 ([nativehost.py:150](C:/Users/lately07/Desktop/Folder%20Group/sentinel-guard/agent/sentinel/nativehost.py:150)).
- **Cache digest cost can erase cache value.** Do not hash a 64 MB YARA pack on every file. Compute immutable manifests when rules load and invalidate them atomically when updates publish.
- **Local clamd is unauthenticated.** With “unknown name means strong,” a spoofed local daemon can manufacture detections. Same-user malware already has broad power, but this makes Sentinel a convenient destructive deputy; process ownership/identity and port-conflict handling deserve a recorded threat-model decision.
- **Findings currently lack structured signature identity.** Policy based on human-readable `detail` will be brittle. Add `signature_id` before evidence-based quarantine is activated.

This was a read-only design review. I did not run pytest, Node tests, ClamAV, Defender, or the scope script.