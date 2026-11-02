# Edge-case test round (2026-11-02)

Five files in `tests/codex/` contain 35 test functions (42 collected cases with parameters). The two-stage policy test checks 93,312 combinations. All payloads are harmless synthetic bytes. No EICAR or malware sample is written to disk. Python AST parsing succeeded; pytest was not run because this sandbox denies its temporary folder. Claude should run the tests and distinguish defects from test assumptions.

## Expected failures on the current code

| Test | Expected behavior and current code path |
|---|---|
| `test_prepended_zip_is_not_certified_clean` | `core.py:126` recognizes ZIP only at byte zero. A valid prefixed ZIP is likely trusted clean without child enumeration (R11 invariant 7). |
| `test_embedded_zip_at_nonzero_offset_is_not_certified_clean` | `archive.py:87` recurses only when a stored member begins with a ZIP signature. A valid ZIP following a member preamble is recorded as fully inspected without its nested child (invariant 7). |
| `test_data_descriptor_size_disagreement_is_opaque` | `archive.py:32-34` accepts the data-descriptor flag without checking descriptor values. `zipfile` may read the central-directory size and mark the conflicting member inspected (invariant 7). |
| `test_unicode_extra_name_conflict_is_not_full_coverage` | `archive.py:23-36` compares method, encryption and size but not the Unicode path extra field. A different extractor can choose the conflicting name (invariant 7). |
| `test_adapter_baseexception_becomes_typed_failure` | `orchestrator.py:200` catches `Exception`, so a custom `BaseException` escapes instead of producing a typed stage error (invariant 7). |
| `test_cache_clock_reversal_does_not_extend_trust` | `cache.py:100,130-131` stores expiration only. A lookup before the original store time can reuse the clean verdict, extending its wall-clock life (invariant 12). |
| `test_restore_rejects_replaced_parent_directory` | `quarantine.py:119-123` creates under `original.parent` without rejecting a replacement directory symlink; the restored bytes can land in a redirected folder (invariant 13). Windows feature test skips if directory symlinks cannot be created. |
| `test_payload_in_alternate_stream_is_not_certified_clean` | `identity.py:103-146` measures the opened unnamed stream; `core.py:126` does not enumerate NTFS alternate streams. The base file can be trusted clean despite a second stream (invariant 7). Windows feature test skips when ADS is unavailable. |

The remaining tests are expected to pass or to expose additional faults. They cover duplicate ZIP names, overlapping offsets, exact byte bounds, sparse logical size, four concurrent readers, two restore items with one path, rollback on simulated disk full, tampered blob detection, frame fragmentation and length bounds, malformed JSON, and hostile path forms. Windows-specific tests name their skip reason.

## Cases not expressed as deterministic tests in this round

- Creating `CON`, `NUL`, or `COM1` as files, opening `\\.\\` device paths, and 8.3 aliases can interact with real devices or depend on volume configuration. No device path is opened by these tests.
- Real junction and mount-point loops, a directory replaced mid-walk, case-sensitive NTFS directories, EFS, cloud/offline placeholders, and exclusive Windows locks need specific filesystem or service configuration. The directory replacement test uses a disposable symlink as the safe reparse analogue.
- A file renamed or truncated during every Gate v2 stage, ChangeTime rollback, and quarantine during restore require a reliable synchronization hook at the I/O boundary. Existing tests already cover same-size rewrites and several cancellation and changed-generation cases; timing-only tests would be flaky.
- ZIP64 lying sizes, dual end-of-central-directory records, PE/PDF ZIP polyglots, Deflate bombs at every budget, and child starts inside another member need parsers or bounded fixtures beyond the six deterministic in-memory differentials added here.
- A permanently stalled event consumer cannot be allowed to leave a test thread running. The existing R15 admission test covers the impossible-capacity termination case; this round does not start an unjoinable consumer.
