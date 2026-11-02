# R8a — ClamAV 1.5.4 engine internals, read from source

The current directory is a checkout of the ClamAV source at tag
`clamav-1.5.4` (C and Rust). Read the code itself, not only the docs.

## Questions

1. **Architecture map.** Directory/module map of `libclamav/`,
   `libclamav_rust/`, `clamd/`, `common/`, `freshclam/`, `libfreshclam/`:
   what each part does, the main structs (`cl_engine`, `cli_ctx`, `fmap_t`,
   scan options, layer/recursion stack, evidence/alerts), who owns what.
2. **One scan end to end.** Trace INSTREAM in clamd from the socket read to
   the reply string: every function on the path (`clamd/` → `cl_scanmap_callback`
   / `cl_scandesc*` → `cli_magic_scan*` → file-type dispatch → matchers →
   result). Give the call chain with `path:line` for each hop.
3. **Matchers.** Hash matching (MD5/SHA1/SHA256, size-keyed, section hashes),
   Aho-Corasick and Boyer-Moore body matching, logical signatures (subsignature
   evaluation, offsets, container/target-type constraints), bytecode execution
   hooks, YARA subset, fuzzy image hash. For each: data structures, when it
   runs, what bytes it sees (raw vs normalized vs decompressed), its limits.
4. **Results and verdict.** How a detection is recorded (`cli_append_virus`
   or its 1.5 equivalent), `CL_VIRUS`/`CL_CLEAN`/`CL_E*` codes, allmatch vs
   first-match, heuristic precedence, how "potentially unwanted" and
   `Heuristics.*` are produced, how the final name returned to clamd is chosen.
5. **Limits and error paths — the core of this round.** Every place where the
   engine stops looking: `MaxScanSize`, `MaxFileSize`, `MaxRecursion`,
   `MaxFiles`, `MaxScanTime`, `MaxEmbeddedPE`, `MaxHTMLNormalize`,
   `MaxHTMLNoTags`, `MaxScriptNormalize`, `MaxZipTypeRcg`, `MaxPartitions`,
   `MaxIconsPE`, `MaxRecHWP3`, `PCRE*` limits, timeouts. For each: the check
   (`path:line`), what is returned to the caller, whether the overall answer
   can still be "OK", and whether `AlertExceedsMax` changes that. Then list
   every other code path where a parse error, allocation failure, unsupported
   format or truncated input leads to `CL_CLEAN`/"OK" rather than an error.
   Produce one table: condition → code location → result seen by an INSTREAM
   client → coverage meaning for Sentinel.
6. **Concurrency and reload.** clamd thread pool, how RELOAD swaps engines,
   what a scan in flight sees during reload, and what VERSION reports when.

## Deliverable

Sections 1–6 with tables, then "Implications for Gate v2": the exact
conditions Sentinel must treat as incomplete coverage, the configuration it
must set, and the signals (if any) clamd exposes that Sentinel currently
ignores.
