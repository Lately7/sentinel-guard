# Codex review — round 4 (read-only, new account, session 01a19b67-9e36-7060-a00d-f2afddbbac42)

Prompt: `docs/handoff/PROMPT_CODEX.md` verbatim, `codex exec --sandbox read-only`.
Run 2026-11-02 while C1 was staged but not yet committed (so its table is one step behind).
Claude verified RT-010 and RT-011 against the code: both confirmed. RT-011 predates the gate
(`__main__.py` at eb556b5); RT-010 is new gate code.

## Codex answer (verbatim)

## Review outcome

No `CODEX_TASK_*.md` exists, so this is review mode. HEAD is still `eb556b5`; none of C1–C4 has been committed.

| Planned work | Current state |
|---|---|
| C1 | Not committed, but its six intended files are staged. The icon-only hunk of `tray.py` is staged while gate changes in the same file remain unstaged. |
| C2a | Gate implementation and `tests/test_gate.py` are present but uncommitted on `main`, not on a non-release branch. `docs/` must not be swept into this commit accidentally. |
| C2b | Absent: no `docs/baseline.md`. |
| C3a–C3f | Absent. The old Defender API, weak cache identity, partial-coverage bug, old governance, single body read, and socket-only ClamAV client remain. |
| C4 | Absent: neither pinned round-1 task file exists. |

Repository/document difference: `PROJECT_CONTEXT.md` calls `sentinel.ico` untracked; it and the other C1 assets are now staged. `tray.py` is `MM`. Otherwise HEAD and the described gate worktree match the handoff.

## Findings

The tests below are proposed and were not run.

- **RT-001 — Weak ClamAV names can cause destructive action — High.** Evidence: [clamav.py:228](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/clamav.py:228>) makes every name except `Heuristics.*`/`PUA.*` critical; [protection.py:23](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/protection.py:23>) quarantines every malicious verdict. Existing [test_gate.py:109](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/tests/test_gate.py:109>) still locks the rejected rule. Reproduction/test: fake ClamAV returns `Win.Trojan.Suspect-34` for harmless bytes; `test_win_trojan_suspect_only_notifies`. Observed statically: critical verdict and quarantine attempt. Direction: versioned weak-name classifier plus separate action policy.

- **RT-002 — Restore grants global hash trust — High.** Evidence: [quarantine.py:110](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/quarantine.py:110>) defaults `trust=True` and [quarantine.py:139](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/quarantine.py:139>) calls `allow_hash`; [test_agent.py:31](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/tests/test_agent.py:31>) enshrines it. Reproduction/test: restore a harmless marker, copy identical bytes to another path, expect detection there; `test_restore_creates_path_hash_exception_only` as strict xfail. Observed statically: the second path is globally allowed. Direction: path+hash restore exception; separate explicit Trust action.

- **RT-003 — Watcher includes Sentinel’s data directory — Medium.** Evidence: [watcher.py:53](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/watcher.py:53>) filters only quarantine claim filenames. Reproduction/test: set a temporary `SENTINEL_HOME` inside a watched temporary tree and submit its database/rule files; `test_data_directory_is_excluded`. Observed statically: they enter the pending queue. Direction: canonical data-directory exclusion before queueing.

- **RT-004 — Incomplete scans can appear clean — High.** Evidence: oversized files receive partial/skipped state at [scanner.py:165](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/scanner.py:165>), but an oversized ZIP clears it at [scanner.py:98](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/scanner.py:98>); the verdict still derives only from findings at [verdict.py:61](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/verdict.py:61>). Coverage text is hard-coded at [scanner.py:208](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/scanner.py:208>). Reproduction/test: reduce limits, scan a harmless oversized ZIP/no-hit file, require incomplete/not-trusted-clean; `test_partial_no_hit_is_not_trusted_clean`. Observed statically: label and CLI exit remain clean/0. Direction: C3c plus Contract v1 coverage/status separation.

- **RT-005 — Layers can inspect different file generations — High.** Evidence: oversized rules reopen the path at [scanner.py:181](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/scanner.py:181>), ClamAV reopens it at [clamav.py:182](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/clamav.py:182>), and Defender later scans the pathname at [scanner.py:137](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/scanner.py:137>). Reproduction/test: use harmless A/B content and injected layer callbacks to change the temporary file; `test_change_between_layers_is_incomplete`. Observed statically: only size/mtime is rechecked after ClamAV, and Defender is not revalidated. Direction: bind layers to one handle/identity and validate before and after path-based stages.

- **RT-006 — Native framing assumes one complete body read — Medium.** Evidence: [nativehost.py:194](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/nativehost.py:194>). Reproduction/test: a synthetic `BinaryIO` returns the JSON frame in short chunks; `test_short_body_reads_until_complete`. Observed statically: the first fragment becomes bad JSON and remaining bytes desynchronize framing. Direction: bounded exact-read loop.

- **RT-007 — CLI/self-data exclusions are inconsistent — Medium.** Evidence: CLI traversal has no exclusion at [__main__.py:14](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/__main__.py:14>); ScanJob compares non-canonical paths at [scanjob.py:42](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/scanjob.py:42>). Reproduction/tests: scan a parent of temporary `SENTINEL_HOME`, then use a temporary alias/reparse path; `test_cli_walk_excludes_sentinel_data` and `test_scanjob_exclusion_uses_realpath`. Observed statically: CLI includes it, while ScanJob can miss aliases. Direction: one canonical exclusion helper shared by all entry points.

- **RT-008 — Defender failure/timeout is reported as clean — High.** Evidence: [defender.py:64](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/defender.py:64>) returns the same empty list for clean and failures; [scanner.py:138](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/scanner.py:138>) maps every empty list to clean. `is_active()` is permanently cached at [defender.py:39](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/defender.py:39>). Reproduction/tests: injected runner timeout/nonzero-without-threat; `test_timeout_is_not_clean`, `test_exit_two_without_threat_is_error`. Observed statically: both become clean. Direction: C3a typed result, runner injection, refreshable active state.

- **RT-009 — Stale and incomplete results are cacheable — High.** Evidence: gate identity uses only rule counts and cached ClamAV version at [scanner.py:50](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/scanner.py:50>); every result is stored at [scanner.py:144](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/scanner.py:144>); ClamAV identity stays cached for 60 seconds at [clamav.py:318](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/engine/clamav.py:318>). Reproduction/tests: replace a rule with same-count content or recover a failed fake engine; `test_same_count_rule_replacement_invalidates_cache`, `test_transient_failure_is_not_cached`. Observed statically: the old result can be reused. Direction: C3b content digest, explicit cacheability, reload invalidation.

- **RT-010 — Failed signature updates suppress automatic retry — Medium.** Evidence: ClamAV and YARA timestamps advance regardless of success at [tray.py:170](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/tray.py:170>) and [tray.py:181](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/tray.py:181>). Reproduction/test: fake each updater returning `error: synthetic failure`; `test_failed_engine_update_does_not_advance_success_timestamp`. Observed statically: ClamAV retry is delayed four hours and YARA retry 24 hours. Direction: record success time only on `ok`; track failed attempts separately with short backoff.

- **RT-011 — CLI mixed-result precedence contradicts the locked decision — Medium.** Evidence: [__main__.py:46](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/__main__.py:46>) and [__main__.py:61](</C:/Users/lately07/Desktop/Folder Group/sentinel-guard/agent/sentinel/__main__.py:61>). Reproduction/test: one suspicious synthetic result plus one unreadable temporary target; `test_suspicious_plus_unreadable_exits_three`. Observed statically: exit 1, while locked precedence requires `2 > 3 > 1 > 0`. Direction: calculate malicious/failure/suspicious flags independently.

## Required before round 1a

Claude must provide:

1. Reviewable C1, C2a, C2b and C3a–C3f commits, ending at a clean C3f HEAD.
2. `docs/baseline.md` with the exact C2a hash and actually observed pytest/Node/ClamAV results.
3. C3a Defender runner seam; C3b cache fixes; C3c coverage fixes; C3e exact reads; C3f keyword-only `ClamdClient` injection.
4. C3d governance: revised rejected tests, updated `AGENTS.md`, canonical RT registry including disposition of RT-008–RT-011, and a tested scope checker.
5. `CODEX_TASK_1a.md` and `CODEX_TASK_1b.md`, both pinned to C3f and the scope-script digest, with skip allowlists and exact commands.
6. No production commit between rounds 1a and 1b.

I modified no files and ran no test suite. `git log`, `git status`, repository inspection, and `git diff --check` were run read-only.