# R8c — ClamAV 1.5.4 signatures, updates and clamd protocol, read from source

The current directory is a checkout of the ClamAV source at tag
`clamav-1.5.4`. Build on R8a/R8b in `docs/research/` of the Sentinel
repository if they exist.

## Questions

1. **Signature database.** Every database file type ClamAV loads (`.hdb`,
   `.hsb`, `.mdb`, `.msb`, `.imp`, `.ndb`, `.ldb`, `.cdb`, `.cbc`, `.idb`,
   `.pdb`, `.wdb`, `.gdb`, `.fp`, `.sfp`, `.ign`, `.ign2`, `.crb`, `.yar`,
   `.ftm`, `.info`, `.cfg`…): loader function (`readdb.c`), purpose, what a
   match from it means. How false-positive (`.fp/.sfp`) and ignore lists work,
   and how Sentinel could add its own trusted-file list the ClamAV way.
2. **Names.** How a returned name relates to the database and signature type;
   whether the name alone can tell a hash match from a generic/logical/
   bytecode/heuristic match; the `.UNOFFICIAL` suffix; how Sentinel's planned
   weak/strong name policy (PROJECT_CONTEXT.md §11 R6) should be grounded.
3. **CVD/CLD and freshclam.** Signing and verification, incremental updates
   (cdiff), `TestDatabases`, what happens on a corrupted or old database,
   version numbering, `FailIfCvdOlderThan`, and what Sentinel must check
   before calling the layer "ready".
4. **clamd protocol.** Every command (`PING`, `VERSION`, `VERSIONCOMMANDS`,
   `STATS`, `RELOAD`, `INSTREAM`, `FILDES`, `IDSESSION`, `ALLMATCHSCAN`…):
   framing, limits, error strings, which commands could give Sentinel more
   information than it uses now (e.g. all matches, stats, per-scan details).
   What a client can and cannot learn from one INSTREAM reply.
5. **Map to Sentinel.** Read `agent/sentinel/engine/clamav.py` and
   `agent/sentinel/engine/scanner.py` in the Sentinel repository. Line by line,
   compare what Sentinel sends, which config it writes, how it parses replies,
   with what ClamAV actually does. List every mismatch as an RT finding (reuse
   RT-001…RT-027 when the same; new ones from RT-028), with harmless test.

## Deliverable

Sections 1–5 with tables, then "Implications for Gate v2": the ClamAV
adapter contract Gate v2 should implement (inputs, outputs, statuses,
evidence strength, readiness checks).
