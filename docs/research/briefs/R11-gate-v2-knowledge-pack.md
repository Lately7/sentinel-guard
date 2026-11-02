# R11 — Gate v2 knowledge pack and specification

Read everything in `docs/research/` (R8a–R10 and R12a–d: YARA-X, capa, osquery, Wazuh) and `docs/handoff/` (r1–r7),
plus the current gate code (`agent/sentinel/engine/`, `scanjob.py`,
`watcher.py`, `protection.py`, `quarantine.py`, `nativehost.py`).

Write the single document an engineer (you, Codex, in a later
implementation round) needs to build Gate v2 from scratch and get it right:

1. **Knowledge digest.** The facts from R8–R10 that constrain the design,
   each with its source section. Nothing decorative.
2. **Invariants.** Numbered, testable statements Gate v2 must never violate
   (e.g. a failed, partial, timed-out, cancelled or unverified engine result
   never yields trusted-clean; one file identity per scan across all layers;
   no action on unverified evidence; bounded memory/time per file).
3. **Architecture.** Modules, responsibilities, data flow, threading and
   cancellation, the per-file state machine, the `ScanEvent` stream (§10 of
   PROJECT_CONTEXT.md), caching rules, and how it replaces today's
   `Scanner` without breaking callers (adapter).
4. **Contracts.** Exact Python types/signatures: scan request, per-engine
   result (status, verdict, coverage ranges, evidence with strength,
   engine/db versions, timings, errors), final decision, action decision with
   reason codes. Versioned.
5. **Engine adapters.** Sentinel core, rules/YARA-X, ClamAV (from R8c),
   Defender, new analyzers recommended by R7/R10 — inputs, outputs, statuses,
   evidence strength, readiness checks, limits.
6. **Verdict and action policy.** Exact rules (tables), consistent with the
   locked decisions; PUA handling; EICAR; partial coverage; conflicting
   engines; user trust vs restore.
7. **Test plan.** Unit, property/fuzz, integration (fake and real clamd),
   concurrency/cancellation, FP corpus, performance budgets — all with
   harmless synthetic inputs; the acceptance criteria per milestone.
8. **Implementation plan.** Ordered milestones small enough to review, each
   with the files it creates, and what Claude must verify before merging.
9. **Open decisions** that need the owner.
