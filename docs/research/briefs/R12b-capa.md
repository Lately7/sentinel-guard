# R12b — capa v10.0.0 and capa-rules, read from source

The current directory is a checkout of Mandiant capa at tag `v10.0.0`; the
rules are in the sibling folder `..\capa-rules` (master). Test-data folders
were deliberately not checked out. The locked decision is: capa is optional
and **explanation only**, never a verdict source (PROJECT_CONTEXT.md §7.1).

## Questions

1. **Pipeline.** From `capa <file>` to the result document: loaders and
   feature extractors (vivisect, IDA, Ghidra, Binary Ninja, dnfile for .NET,
   CAPE/DRAKVUF dynamic reports, the BinExport2 path), feature types
   (API calls, strings, bytes, numbers, offsets, mnemonics, characteristics),
   scopes (file, function, basic block, instruction; process/thread/call for
   dynamic), rule matching engine, the result schema. `path:line` per hop.
2. **Rule format and semantics.** capa rule YAML: features, logic
   (`and/or/not/optional/N or more`), scopes, `meta` (ATT&CK, MBC, namespace,
   `lib` rules, `maec`), and how rules reference other rules. Pick 10
   representative rules from `capa-rules` (persistence, anti-analysis,
   cryptography, injection, communication, ransomware-related file
   operations) and explain what evidence they need.
3. **Cost and limits.** Runtime/memory characteristics of static analysis
   with vivisect on large binaries, timeouts or lack thereof, the
   `--signatures` (FLIRT) library identification, what happens on packed or
   obfuscated input (capa's own warnings), .NET support, and which inputs it
   refuses.
4. **Using it safely in Sentinel.** Can it run as a separate, time- and
   memory-bounded subprocess on a file Sentinel already hashed, without
   executing the file? Which output fields should Sentinel store and show to
   explain a detection (capabilities, ATT&CK IDs), and how to avoid capa
   output being misread as a verdict.
5. **Packaging.** Dependencies and size, licence (Apache-2.0), startup time,
   whether the standalone binary or the Python package fits a Windows user
   install, and how rule updates are versioned.

## Deliverable

Sections 1–5 with tables, then "Implications for Gate v2": an optional
explanation-stage contract (when to run, budgets, outputs, how it is shown
in the UI), and the reasons it must never change a verdict.
