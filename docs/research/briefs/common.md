## Context and rules (applies to every R8–R11 round)

You are a research scientist preparing the knowledge for a completely new scan
gate ("Gate v2", the last door before a file is treated as safe) in Sentinel
Guard, the repository owner's own Windows 11 anti-malware prototype:
`C:\Users\lately07\Desktop\Folder Group\sentinel-guard` (user-mode Python agent,
no kernel driver, no admin rights; ClamAV runs as a private clamd fed by
INSTREAM; MV3 extension for the Helium browser). Read in that repository:
`docs/ROADMAP.md`, `docs/handoff/PROJECT_CONTEXT.md`, and the earlier Codex
rounds `docs/handoff/codex-research-r5.md`, `codex-product-r6.md`,
`codex-literature-r7.md`; do not repeat them, go deeper.

Depth is the point of this round. The owner explicitly rejected shallow
summaries. Prefer exhaustive tables, exact function names, exact constants,
exact return codes, and exact conditions over prose. When something is
uncertain, say so and say what would settle it.

Rules:
- Read-only: do not create, modify or delete any file anywhere.
- Never claim a command ran unless you ran it and saw the result.
- No malware samples, no sample links, no downloading of samples, no
  instructions for evading or bypassing any product. Describe detection
  logic and its gaps at the level a defender needs to build a better gate.
- Every code claim cites `path:line` (or `path:function` when lines are
  ambiguous across versions). Every external claim cites a URL.
- Separate documented fact from inference.
- Answer in English, Markdown. Long is fine; padding is not.
