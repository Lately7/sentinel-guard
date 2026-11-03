# RED26 — scan policy and orchestrator, second pass

Tests are in `tests/codex/test_red26_policy.py`. They were checked against the implementation but not run; this round forbids pytest. These findings are distinct from the fixed-partial clean label, stale stage plan, and final-stage deadline overrun in RED6 and RED17.

## High — weak ClamAV heuristic can trigger automatic quarantine

**Test:** `test_weak_clamav_name_never_auto_quarantines`.

**Attacker model:** A downloaded file receives a verified ClamAV name in the `BC.Heuristics.` family. No malware bytes are needed for the regression test; it supplies the stage result in process.

**Steps and effect:** `classify_clamav_name` marks `BC.Heuristics.Suspect` as supporting, so `decide` returns `SUSPICIOUS`. The legacy action branch accepts any verified, range-bound ClamAV raw name except ones beginning `Heuristics.` or `PUA.`. It therefore puts this supporting hit in `legacy_ids` and selects `QUARANTINE` when automatic quarantine is enabled. The production scanner requests the legacy action policy, so the discrepancy reaches the normal file scan. A weak heuristic alone can remove a legitimate file.

**Exact lines:** `agent/sentinel/gate_v2/policy.py:15-16,44-51,193-199,237-246,248-264`; `agent/sentinel/engine/scanner.py:207-210,221-224`.

**Proposed fix:** Make the legacy branch use the same effective category and strength classification as the verdict path. Only verified conclusive malware evidence may auto quarantine; supporting names stay at review or notification.

**Evidence:** Proven by the test's policy and action construction; execution is pending Claude.

## Medium — a weak hit hides a required engine timeout

**Test:** `test_weak_hit_preserves_required_timeout_reason`.

**Attacker model:** A crafted file causes one required stage to time out while another required stage returns a weak, verified ClamAV name.

**Steps and effect:** `decide` records `ENGINE_TIMEOUT` internally and makes the decision noncacheable. The other stage returns the supporting name `Heuristics.Suspect`. The weak-evidence branch then emits only `WEAK_DETECTION` as the final reason. The action selector sees `SUSPICIOUS` and chooses notification instead of its `UNKNOWN` retry route. The UI's structured scan result exposes only the final reason codes, so the timed-out required check is hidden from that summary. This can leave an incomplete scan without a retry request.

**Exact lines:** `agent/sentinel/gate_v2/policy.py:157-158,193-202,211-217,243-245,267-270`; `agent/sentinel/gate_v2/legacy.py:45-66`.

**Proposed fix:** Carry incomplete reason codes into suspicious and malicious decisions. For suspicious results with an incomplete required stage, preserve the detection while requesting a retry or otherwise making the gap explicit to the caller.

**Evidence:** The missing reason is proven by the test logic; the absence of a later retry depends on the caller's action handling and is inferred.

## High — hard-link deduplication can lose the original bytes after a rename

**Test:** `test_renamed_queued_hardlink_is_scanned_or_reported`.

**Attacker model:** An ordinary user process controls a downloaded file and two hard links to it while a smart scan is running.

**Steps and effect:** Discovery admits the first name and records its file ID in `_seen`. Before the scan job opens that queued name, the attacker moves it outside the source and puts harmless bytes at the same path. The scan job discards the `Target` identity and scans only the path. Discovery then treats the second name, which still leads to the original marker bytes, as a duplicate. The scan reports complete while those bytes were never scanned. The test uses a harmless marker and a scanner stub that records the actual bytes opened at each path.

**Exact lines:** `agent/sentinel/gate_v2/scope.py:223-232`; `agent/sentinel/scanjob.py:149-175`.

**Proposed fix:** Bind each queued `Target` to the identity opened by the scan, and do not treat other names as covered until that identity was scanned. If a queued path changes or vanishes, scan the surviving hard link or record a coverage gap.

**Evidence:** Proven by the in-process rename and hard-link test logic; execution is pending Claude.

## Other probes

Required `TIMEOUT`, `UNAVAILABLE`, `CHANGED`, and runtime-partial stages enter `incomplete` and cannot produce trusted clean or a cacheable negative when no accepted detection masks the verdict (`policy.py:142-186,200-217`). A fixed-partial stage can still return reduced clean, but RED6 and RED17 already report that. `identity.revalidate(..., rehash=True)` accepts a same-inode, same-size rewrite only when the default-stream SHA-256 still matches (`identity.py:230-240`); timestamp changes alone are intentionally ignored. A hard-link alias to the same file likewise satisfies the byte identity, but quarantine separately inventories names and checks the expected canonical path (`quarantine.py:127-149`). No separate wrong-file action is asserted for that identity behavior.
