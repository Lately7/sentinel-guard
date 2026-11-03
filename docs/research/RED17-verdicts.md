# RED17 — Verdict and evidence integrity

The tests below are regression probes, read against the implementation but not run in this sandbox. Each uses only temporary files or in-memory bytes and the temporary `SENTINEL_HOME` fixture.

## High — Stale file head omits Defender

**Test:** `test_plan_uses_measured_head_for_defender_applicability`

**Attacker:** An ordinary user process controls a downloaded file while it is being scanned.

**Steps and effect:** Put plain text at `document.txt` for the initial read, then replace its bytes with `MZ` content before the measured scan starts. `scan_file` reads the head at `agent/sentinel/engine/scanner.py:183-192`; `_scan` builds the adapter plan from that head at `agent/sentinel/engine/scanner.py:202`. Defender is required only when `filetype.sniff(head)` or the extension is risky at `agent/sentinel/engine/scanner.py:158-168`. The orchestrator measures the later bytes at `agent/sentinel/gate_v2/orchestrator.py:143-155`, but runs the already chosen adapters at `agent/sentinel/gate_v2/orchestrator.py:172`. Thus the PE bytes get a verdict without the applicable Defender stage, potentially `trusted_clean` (`agent/sentinel/gate_v2/policy.py:142-156,210`). The test swaps the harmless file between planning and measurement and requires either a Defender result or an unknown verdict. **Proven by the test logic; execution pending Claude.**

**Proposed fix:** Derive file type and engine applicability from the measured handle or its bound reader, then construct the required stages. If the pre-read head differs from the measured head, replan or return unknown.

## High — Fixed partial negative is labeled clean

**Test:** `test_fixed_partial_without_full_negative_cannot_be_clean`

**Attacker:** A downloaded file places content between the configured front and tail scan windows.

**Steps and effect:** The test-only marker rule sees neither the middle marker nor a full file. Core reads at most the resident limit (`agent/sentinel/gate_v2/core.py:141-153`); JSON rules read the front and a bounded tail (`agent/sentinel/gate_v2/rules.py:25-29,171-188`). Both report `fixed_partial` (`core.py:176-177`; `rules.py:60-65,202-205`). Policy treats fixed partial as a reduced but **clean** verdict at `agent/sentinel/gate_v2/policy.py:167-175,203-210`; projection exposes that as the file label at `agent/sentinel/gate_v2/legacy.py:30-35`. The missed marker proves the negative does not cover these bytes. **Proven by the test logic; execution pending Claude.**

**Proposed fix:** Return unknown when no required negative stage covered the complete file, or expose a distinct partial verdict that cannot be read or recorded as clean. Preserve any positive evidence.

## Medium — Last stage can overrun the deadline and still return clean

**Test:** `test_over_deadline_last_stage_cannot_return_clean`

**Attacker:** A crafted file causes the final adapter to exceed its scan deadline.

**Steps and effect:** The orchestrator checks the deadline before an adapter (`agent/sentinel/gate_v2/orchestrator.py:173-178`). After the adapter returns it only sets `stop = TIMEOUT` for subsequent adapters (`:213-229`). If this was the last adapter, `decide` receives its completed clean result (`:240-242`) and policy returns trusted clean (`agent/sentinel/gate_v2/policy.py:203-210`). The test advances an injected clock beyond the deadline during the sole adapter. **Proven by the test logic; execution pending Claude.**

**Proposed fix:** Recheck elapsed time before accepting a negative from each adapter. Retain conclusive positive evidence on an overrun, but mark an otherwise negative stage timed out and return unknown.

## Probes without a reported finding

`cache_key` includes SHA-256, file identity, size, timestamps, canonical path and gate generation (`agent/sentinel/gate_v2/cache.py:78-90`); `lookup` rechecks the identity (`agent/sentinel/gate_v2/cache.py:139-147`). Policy treats missing, timed-out, changed, and unverified required stages as incomplete (`agent/sentinel/gate_v2/policy.py:142-186`). Result file IDs and measured identities are checked before policy (`agent/sentinel/gate_v2/orchestrator.py:214-224`; `agent/sentinel/gate_v2/policy.py:90-102`). Quarantine checks the current file key and copied SHA-256 against the verdict (`agent/sentinel/quarantine.py:131-149,195-203`). Policy derives its final verdict from evidence rather than the stage verdict field (`agent/sentinel/gate_v2/policy.py:109-140,188-208`), while the current core, rules, Defender and ClamAV adapters derive their stage verdicts from the same evidence (`agent/sentinel/gate_v2/core.py:174-183`; `agent/sentinel/gate_v2/rules.py:62-71`; `agent/sentinel/gate_v2/defender.py:340-346`; `agent/sentinel/gate_v2/clamd.py:402-410`); no file-triggered disagreement path was established. The SHA-256 allow list intentionally covers all byte-identical copies, which the approval text states (`agent/sentinel/service/backend.py:613-620`); restore exceptions require both path and hash (`agent/sentinel/engine/scanner.py:211-216`). No additional finding is asserted for these probes.
