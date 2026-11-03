# Codex task DOCS3: record the fourth install and the ETW investigation

## Allowed paths

Changed: `REVIEWS.md`, `TASKS.md`, `docs/handoff/PLAN.md`, `docs/handoff/NEXT_SESSION.md`. Everything else is
read-only. Write only the facts below; add no figure, cause or result that is not here. Where a fact is an
inference, say so. `PLAN.md` is in Vietnamese; the other three are in English. Match the surrounding style.

## Facts

* 2026-11-03, about 10:26: the owner opened `tools\install_service.cmd` themself (the fourth install), with
  `8b6f043` (SID read after the TOKEN_USER header; the check passes on the child's Start alone).
* Result: 0 FAIL, 14 PASS, 3 SKIP after the restart (0 FAIL, 13 PASS, 3 SKIP before it); `worker_scan` PASS.
* ETW stayed off with `no_start_events`. During the check: Process/3 (DCStart) 11; EventTrace `68fdd900-…`
  opcode 5: 2, opcode 8: 1, opcode 32: 2; no Process/1 in the 5 s after the child was spawned. Status: loss
  during the check 3, total 1,378.
* The install window again looked hung after the steps had finished (10:27:16): a click had put it into
  selection mode (title "Select Administrator"); Esc resumes it.
* Claude ran an eight-agent investigation as a workflow: four investigators (Microsoft documentation; the source
  of krabsetw, ferrisetw, pywintrace, TraceEvent, one-collect, fibratus and Elastic Beats; a code audit of
  `etw.py`; an analysis of the five sessions), one synthesis, three challengers.
* Findings: the ctypes layouts, handles and callback match the SDK; the call order matches the libraries;
  FlushTimer 1 s is standard; `ProcessTrace`'s return code is discarded; about 1,380 events reached the Python
  callback only when the session stopped, so events were held in the session rather than lost in Python (the
  reason is open: unflushed per-CPU buffers, ProcessTrace waiting on quiet per-CPU streams, a rundown written
  before the consumer connected, a GIL stall at service start, or the child created before the asynchronous
  enable took effect); the loss figure adds unlike units (`truncated` events were delivered; a failed QUERY
  adds 1 to `events_lost`; RealTimeBuffersLost counts 64 KB buffers); EventTrace `68fdd900-…` events can be
  synthetic events delivered when a consumer connects, so opcode 8 is not proof that a rundown completed.
* The three challengers rejected the first plan: tallies read while the ETW thread adds keys could raise and
  turn a passing check into a failure; it had no proof that the consumer was connected; it stopped measuring at
  the first match; a FLUSH response alone cannot tell unflushed buffers from ProcessTrace waiting on quiet
  streams; CloseTrace right after STOP cuts off the last events; the QUERY/FLUSH buffer is smaller than the
  ControlTrace documentation asks.
* Next: Codex rounds SVC18 (a phased check in `etw.py` that one install can settle: consumer connected before the
  provider is enabled, child A, child B, explicit FLUSH, per-phase counts in the callback, ProcessTrace's return
  code, each loss counter apart) and SVC18V (`verify` waits for the check), reviewed by Claude; then the owner
  reinstalls.

## Build

* `REVIEWS.md`: a new section after the ninth round, "Tenth round: the fourth install and the ETW investigation".
* `TASKS.md`: Codex log rows SVC18 and SVC18V ("in progress") and DOCS3 ("submitted for Claude review").
* `docs/handoff/PLAN.md` §0a: one paragraph after the one on the third install.
* `docs/handoff/NEXT_SESSION.md`: one "Update 2026-11-03, after the fourth install." paragraph after the last
  update.

State no test counts: none were run for this round.
