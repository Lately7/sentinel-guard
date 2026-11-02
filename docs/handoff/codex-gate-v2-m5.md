Implemented K1–K17 on `codex/gate-v2-m5` at the pinned `3cdb0de`. Changes are confined to `agent/sentinel/gate_v2/` and `tests/gate_v2/`; I did not commit.

| Finding | Change (`file:line`) | Covering test |
|---|---|---|
| K1 | `defender.py:295` deduplicates and caps valid names, with unique evidence IDs | `test_k1_multiple_duplicate_invalid_names_and_limit` |
| K2 | `defender.py:194` decodes runner output with Latin-1 | `test_k2_k15_runner_bytes_and_output_limit` |
| K3 | `orchestrator.py:205` retains evidence on generation mismatch | `test_k3_k4_named_hit_survives_change_and_deadline` |
| K4 | `defender.py:290` parses a late named hit before applying the negative timeout rule | Same test |
| K5 | `policy.py:115`, `motw.py:82` apply the two explicit context rules and URL check | `test_k5_k6_context_rule_and_name_policy` |
| K6 | `policy.py:53`, `defender.py:300` classify PUA and riskware names | Same test |
| K7 | `content.py:128`, `orchestrator.py:194` reset recorded reads per stage | `test_k7_stage_ranges_are_local` |
| K8 | `signer.py:112` returns promptly when the trust slot is busy | `test_k8_busy_trust_returns_promptly` |
| K9 | `orchestrator.py:49`, `defender.py:330`, `signer.py:153`, `motw.py:105` bound revalidation and use the measured trust handle | `test_k9_revalidation_is_bounded_and_motw_metadata_only` |
| K10 | `lnk.py:130` treats ordinary files as `NOT_LNK` and parses oversized links as fixed partial | `test_k10_k11_link_candidates_and_partial` |
| K11 | `lnk.py:59` checks bounded strings, LinkInfo, environment blocks, and ID lists | Same test |
| K12 | `motw.py:22`, `motw.py:114` distinguish absent streams from read errors and decode UTF-16 BOMs | `test_k12_motw_absence_error_and_blocklist`, `test_k12_utf16_zone_stream` |
| K13 | `policy.py:18` names the declared-coverage exception | `test_k13_declared_coverage_exception` |
| K14 | `test_m5_defender.py:127` performs a real rename swap | `test_swapped_before_defender_stage` |
| K15 | `defender.py:34`, `signer.py:75` move Windows bindings to module level and close runner stdout | `test_k2_k15_runner_bytes_and_output_limit`, `test_k15_job_kills_grandchild`, `test_k15_wintrust_with_open_handle` |
| K16 | `defender.py:79`, `defender.py:225` add deadline-aware applicability, numeric platform ordering, a short unknown retry, and cancellable waiting | Three `test_k16_*` tests |
| K17 | `defender.py:279` uses the measured canonical path and a process-wide slot | `test_k17_defender_pool_serializes`, `test_k17_uses_measured_canonical_path` |

**M1–M4 files changed:** `content.py` for per-stage reads and OS handles; `orchestrator.py` for deadline-bound revalidation and evidence retention; `policy.py` for name classification, context rules, and declared coverage. The new regressions are in [test_m5_round2.py](<C:/Users/lately07/Desktop/Folder Group/sentinel-guard-gate-v2/tests/gate_v2/test_m5_round2.py>).

`git diff --check` and AST parsing of 22 Gate v2 and M5 test files passed. Three in-memory checks passed. **Pytest and the Windows-only runner tests remain unrun in this sandbox**, so Claude’s suite run is the remaining verification step.

For M6, cache integration needs to honor the new fixed-partial and limit results, retained unaccepted evidence, and normal `NO_ORIGIN` completion. `cache.py`, `legacy.py`, and M6 tests were untouched.