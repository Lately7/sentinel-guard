# R12a — YARA-X v1.22.1, read from source

The current directory is a checkout of VirusTotal YARA-X at tag `v1.22.1`
(test-data folders were deliberately not checked out). Sentinel already uses
the `yara-x` Python package for its rules layer
(`agent/sentinel/engine/signatures.py`, `agent/sentinel/yarafeed.py`).

## Questions

1. **Architecture.** Crates and their roles (`lib/`, `parser/`, `fmt/`,
   `py/`, `capi/`, `cli/`…); the path from rule source to compiled rules
   (parser → AST → IR → WASM code generation) and from `Scanner.scan()` to
   match results. Cite `path:line` for every hop.
2. **Python binding.** Exactly what `yara_x.Compiler`, `Rules`, `Scanner`
   expose in `py/`: timeouts, `max_matches_per_pattern`, global variables,
   console/module outputs, error types, thread safety, whether a `Scanner`
   can be shared across threads, memory behaviour for large inputs, whether
   scanning a file path memory-maps it. What Sentinel should use instead of
   reading 64 MB into a Python `bytes` (`scanner.py` today).
3. **Modules relevant to Windows files.** `pe`, `dotnet`, `lnk`, `macho`,
   `elf`, `hash`, `math`, `magic`, `console`, `string`, `time`, `vt`: what each
   parses, its limits, what happens on malformed input, and which fields a
   file gate could use as evidence (signatures/Authenticode in `pe`, LNK
   target/arguments, .NET metadata). Note what is NOT verified (e.g. does
   `pe.signatures` verify the chain, or only parse it?).
4. **Limits and failure semantics.** Timeout behaviour (partial results?),
   per-pattern match caps, slow-pattern/“atom quality” warnings at compile
   time, rules that fail to compile, what a scan returns when a module
   cannot parse the file. Produce a table: condition → behaviour →
   what Sentinel must record as coverage.
5. **Rule quality and false positives.** How YARA-X reports slow or
   problematic rules; how YARA Forge packages (core/extended/full) should be
   filtered; how to attach provenance (rule name, namespace, meta: author,
   score, reference) to Sentinel evidence.
6. **Compare with Sentinel today.** Read `agent/sentinel/engine/signatures.py`
   and `agent/sentinel/yarafeed.py` in the Sentinel repository and list every
   mismatch or risk as an RT finding (registry continues at RT-037), with a
   harmless test (test-only rules and synthetic bytes; no samples).

## Deliverable

Sections 1–6 with tables, then "Implications for Gate v2": the YARA-X adapter
contract (inputs, statuses, coverage, evidence strength, provenance,
performance budget) and which YARA-X modules Gate v2 should use for
structure-aware analyzers (PE, .NET, LNK) instead of writing its own parsers.
