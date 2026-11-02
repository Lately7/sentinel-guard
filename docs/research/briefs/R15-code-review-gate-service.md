# Codex round R15 — independent code review of Gate v2 and the service boundary

Read-only review round of this project's own code. Do not create, modify or delete any
file. Answer in English; Claude verifies each finding and records it in `REVIEWS.md`.

## Context

Sentinel Guard is the repository owner's own Windows 11 anti-malware prototype. Branch
`gate-baseline`. Read: `AGENTS.md`, `docs/handoff/PROJECT_CONTEXT.md` (§§7, 10–12),
`docs/research/R11-gate-v2-knowledge-pack.md` (§§2, 3, 6), `docs/research/R13b-design-discussion.md`,
`REVIEWS.md` (RT registry and the tables F1–F8, G1–G8, H1–H9, J1–J4),
`docs/handoff/CODEX_TASK_GATE_V2_M5_R2.md` (K1–K17, findings already known).

**Do not re-report** anything in those tables, and do not review `defender.py` or
`gate_v2/analyzers/`: they are not merged and are in another round.

## Scope, in priority order

1. `agent/sentinel/gate_v2/`: `contract.py`, `coverage.py`, `policy.py`, `identity.py`,
   `events.py`, `orchestrator.py`, `content.py`, `archive.py`, `evidence.py`, `core.py`,
   `rules.py`, `clamd.py`, `winnet.py`.
2. `agent/sentinel/service/`: `protocol.py`, `authz.py`, `core.py`, `winpipe.py`,
   `client.py`, `host.py`, `worker.py`, `workerclient.py`, `workermain.py`.
3. `agent/sentinel/quarantine.py`, `protection.py`, `nativehost.py`, `watcher.py`,
   `engine/scanner.py`, `extension/src/background.js`, as they meet the two above.

## What to look for

Logic defects in this code, proved by reading it:

* A state that reaches `clean`, `trusted_clean`, a cacheable decision or an action
  when R11 §2 forbids it. Walk `policy.decide` and `should_auto_quarantine` as a truth
  table, including stages that are not required, empty inputs and zero-size files.
* A returned result or detection lost anywhere between adapter and final decision.
* Identity: a generation check that passes when bytes differ; a path used after a
  handle was the authority; hard links, alternate streams, reparse points, long paths,
  case and short names; ChangeTime assumptions.
* Coverage: a range or object count that overclaims; `archive.py` limits; a ZIP whose
  central and local headers disagree; ZIP64; stored versus declared sizes; a nested
  member that is counted as inspected but was not read.
* Concurrency and lifetime: races in `events.py` admission, in the clamd readiness cache
  and reload state, in `ServiceCore` plans and buckets, and in `WorkerSession`;
  leaked handles; threads that survive their purpose; deadlocks when a consumer stalls.
* Waits not bounded by the request deadline or not honouring cancel.
* The service boundary: token and integrity checks in `winpipe.py`, name-squatting of the
  pipe, impersonation failure paths, DACL construction, what a same-user process can reach,
  frame-parsing limits, plan replay and session binding, and whether any "user" operation
  can weaken protection. The worker's token, handle inheritance, job limits, environment
  and reply parsing.
* ctypes correctness: structure layouts on 64-bit Windows, `argtypes`/`restype`, handle
  truncation, `GetLastError` read too late, buffer sizes, callback lifetime.
* Tests that assert less than their name claims, and fakes kinder than the real thing.
  J1 is the model: a fake clamd that answered at once hid a 0.25 s timeout.

## Reporting

A table first, most severe first: id `R15-n`, severity, `path:line`, one-sentence defect,
concrete input or state → wrong result, invariant or RT id. Then for each finding the code
path, and a pytest sketch that fails today and passes after the fix, using harmless
synthetic data; no real malware, no EICAR on disk, no elevated steps. Mark each finding
**proved by reading** or **needs a run to confirm**, and state what you did not review.
Do not invent findings to fill the table. Never claim a command ran unless you ran it.
Severity reflects effect on a user of this product; a finding of "no issue found" for an
area is useful, so say which areas came out clean.
