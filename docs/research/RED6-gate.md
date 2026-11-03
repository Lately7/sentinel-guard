# RED6 — content scanning and archives

Tests are in `tests/codex/test_red6_gate.py`. They have been checked against the implementation, but pytest was not run in this sandbox.

## 1. Orphaned ZIP local entry is certified clean — high

- **Attacker:** A downloaded file crafted by an ordinary user or malicious site.
- **Steps:** Put the harmless marker in a deflated ZIP member, keep its local header and compressed data, remove its central-directory entry, and append a syntactically valid empty central directory. The raw archive contains no plaintext marker. A local-header recovery extractor can still find the payload, while Python's `zipfile` lists zero members.
- **Effect:** Core and JSON rules read the outer ZIP bytes but inspect no decompressed member. The archive walk records `zip` as complete, so the gate can return `clean` with `trusted_clean=True` for a compressed payload it never inspected. The test requires a non-clean result.
- **Exact lines:** `agent/sentinel/gate_v2/archive.py:103-105` relies only on `infolist()`; `archive.py:156` unconditionally records a complete parser after that list. `agent/sentinel/gate_v2/core.py:159-162` and `agent/sentinel/gate_v2/rules.py:189-192` use that walk. `agent/sentinel/gate_v2/coverage.py:105-115` treats the full outer-byte read with no child debt as full coverage. `agent/sentinel/gate_v2/policy.py:200-210` turns it into a trusted clean result.
- **Fix:** Inventory local file headers and their byte ranges as well as central-directory records. Any orphan, overlap, or contradictory inventory should create opaque child debt and an incomplete parser state. Keep the compressed payload bounded; do not need to extract an orphan to reject a clean claim.
- **Evidence:** The test proves the ZIP shape, the absence of a raw marker, and the gate's expected failure. Extraction by a particular third-party recovery tool is inferred from the retained local header and deflate stream.
- **Test:** `test_orphan_local_zip_entry_is_not_certified_clean`.

## 2. Same-size changes can create a hash of no file generation — high

- **Attacker:** A medium-integrity process with a writable mapping of its own file before the service opens it.
- **Steps:** Change both halves of a fixed-size file through the mapping after the first hash chunk has been read. The first chunk in the hash is from the old generation; the next is from the new generation. The test calls the same measurement helper with `ignore_times=True`, as the Windows bound reader does.
- **Effect:** The helper returns `OK` and stores a SHA-256 that belongs to neither complete generation. Subsequent bound content stages can examine bytes different from those in the measurement, while the Windows reader checks only device, file ID and size. The test requires `CHANGED`.
- **Exact lines:** `agent/sentinel/gate_v2/content.py:72-79` calls `measure_stream(..., ignore_times=os.name == "nt")`; `agent/sentinel/gate_v2/identity.py:157-178` hashes chunks but, with `ignore_times`, compares only the first three generation fields and the byte count. `agent/sentinel/gate_v2/content.py:97-107` also omits timestamps in `_check()` on Windows. `_open_measured` denies sharing a new write handle at `content.py:35-42`, but an existing mapped view is the attack route.
- **Fix:** Bind the digest to the bytes the engines actually read, or rehash the same handle after stage reads and reject any mismatch. A Windows generation check can also incorporate file change time, but it must handle metadata-only touches without allowing changed content to be certified.
- **Evidence:** The test proves the mixed-generation hash acceptance in `measure_stream`. Whether a preexisting writable mapping can mutate during this exact `CreateFileW` sharing mode is inferred and should be verified on the target Windows filesystem.
- **Test:** `test_same_size_change_during_measurement_is_rejected`.

## 3. Unread middle span is displayed as clean — medium

- **Attacker:** A downloaded file with marker bytes placed between the initial resident scan and the tail sample.
- **Steps:** Limit resident scanning to 64 bytes in process, put the harmless marker after byte 100, and scan a file long enough that the last 64 bytes also miss it. The full-file hash still runs, but no marker rule has a matching hash; content engines inspect only front and tail.
- **Effect:** Required content stages report `fixed_partial`; policy emits `CLEAN` with `trusted_clean=False`, and the legacy `label` property still says `clean`. The test checks that user-facing label. This is a misleading negative for bytes no signature engine examined.
- **Exact lines:** `agent/sentinel/gate_v2/core.py:141-153` reads only the resident prefix and marks fixed reduction. `agent/sentinel/gate_v2/rules.py:25-29,172-188,202-205` reads front and tail and reports partial. `agent/sentinel/gate_v2/policy.py:167-175,200-210` maps fixed partial to `CLEAN`. `agent/sentinel/gate_v2/legacy.py:30-35` exposes the clean label.
- **Fix:** Give fixed partial its own non-clean verdict or label, such as `unknown` with a size-limit reason. Preserve the reduced coverage metadata so users can distinguish this from a failed read.
- **Evidence:** Proven by `test_fixed_partial_middle_gap_is_not_labeled_clean`. The existing structured `trusted_clean=False` flag limits the effect for callers that check it.
- **Test:** `test_fixed_partial_middle_gap_is_not_labeled_clean`.

## Other probes

The current code records archive depth, member count, expansion, encrypted members, corrupt entries, and oversized directories as coverage debt (`archive.py:97-145`, `coverage.py:64-115`); very many small entries therefore do not become clean. The hash loop reads sparse files as ordinary logical bytes and checks the final byte count and size, so ordinary growth and shrinkage are rejected (`identity.py:153-174`). Cloud placeholders, oversized files, and unreadable or locked paths return unknown (`identity.py:147-155`, `content.py:38-42`, `orchestrator.py:144-162`). Those paths did not yield another line-backed clean bypass. Existing tests cover duplicate and colliding ZIP names, overlapping local offsets, data-descriptor disagreement, and prefixed polyglots (`tests/codex/test_archive_edges.py`).
