# Codex task SVC17: ETW for processes only, after the first real session

## Allowed paths

Changed: `agent/sentinel/service/etw.py`, `agent/sentinel/service/backend.py` (`_machine_observers` and `status` only),
`agent/sentinel/service/verify.py`. New: `tests/test_svc17.py`. `tests/test_svc11.py` may change where it pins the old
check. Everything else is read-only.

## What the first real session showed (measured on the owner's machine, 2026-11-03)

The service now works: `worker_scan` PASS, 0 FAIL. ETW stayed off with `schema_process_missing`. Status afterwards:
`etw_events_parsed` 1,380 and `etw_events_lost` 373,432, within the few seconds of the check. Raw events seen during the
check, by class GUID and opcode:

* `3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c` (Process) opcode 3: 61. Opcode 3 is DCStart, the rundown of processes already
  running. **No opcode 1 (Start) at all**, so the check's own child was never seen.
* `90cbdc39-4a3e-11d1-84f4-0000f80464e3` (FileIo) opcode 32: 5, opcode 76: 16. **No 67 or 68 (Read, Write).**
* `68fdd900-4a3e-11d1-84f4-0000f80464e3` (EventTrace header) opcodes 5, 8, 32.

So the file events of the whole machine arrive far faster than a Python consumer can take them, and the losses take
process events with them. File events through Python are not workable on this machine. Process events are few.

## Build

1. **Process events only.** Never enable the IO provider, during the check or after. Remove the rate guard's role in
   the check. `status` reports `etw_file_events: "off"` with a reason saying a Python consumer cannot keep up, and the
   measured loss of the last check if there was one.
2. **The check uses what really arrives.** Pass if the service's own pid appears in a DCStart (opcode 3) event whose
   parsed short name matches `python.exe`, the service's own image, so the layout is verified on real data with no
   child needed; and then a Start (opcode 1) of the check's own child is seen within the window, so live starts are
   delivered. If DCStart parses but no Start arrives, the state says exactly that: `no_start_events`. Losses during the
   check are reported separately from the result.
3. **Delivery latency.** `FlushTimer` is 1. Check the session properties against Microsoft's documentation for a
   real-time system logger, and say whether anything else holds events back: buffer count and size, the mode bits,
   or the keyword. Check whether `SYSTEM_PROCESS_KW_GENERAL` alone delivers Start and End, and whether the provider
   needs a different keyword or level for live starts.
4. **On failure, log the bytes that matter.** At WARNING, under `etw check:`, the first 160 bytes in hex of up to 2
   DCStart events for the service's own pid. Only its own: nothing of the user's. Keep the counts line.
5. **Shadow scoring has no source now.** `ShadowObserver` stays wired but is not fed. Its report must not count days:
   status shows that it waits for a file event source, so a reader cannot take an empty month as a result.
6. **`verify`.** The `etw` line: PASS when on, SKIP with the state otherwise, and the loss figure.

Each change needs a test that fails before it. Build canned DCStart and Start payloads from the documented layout; the
real bytes arrive with the next install's log, so say they are not captured ones.
