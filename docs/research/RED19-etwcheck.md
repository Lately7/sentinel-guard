# RED19: phased ETW check

Scope: `agent/sentinel/service/etw.py` after SVC18B. These are in-process tests only. Pytest was not run in this sandbox.

## 1. Unrelated process command line in `etw check:` (medium)

**Attacker and steps.** An ordinary user's process churns PIDs after check child A exits (it sleeps three seconds). If a later unrelated process receives A's PID while the seven-second check still runs, its Process Start is retained in `_raw_starts`. A check failure then selects raw samples by PID membership alone. The event's parent and image are not checked before its first 160 payload bytes are logged as hex. The hex includes the process command line. This is a conditional PID-reuse path, not a claim that an ordinary user can forge the LocalSystem parent PID.

**Effect.** Another user's command line can enter the service's `etw check:` log. The raw event would fail `_parsed`'s parent check, but that does not protect the failure logger.

**Lines.** Child A's lifetime: `etw.py:816-824`; retained PID: `:611`, `:824`; all raw starts retained: `:928-932`; sample selection and payload logging: `:946-960`. The log buffer holds 256 starts (`:608`), so exploitation also depends on the reused event remaining in that buffer until the failure.

**Fix.** Retain a raw sample only after the same event passes the child identity predicate, including parent PID and image, and associate it with the specific child spawn interval. Better, omit command-line bytes from diagnostic samples. **Evidence:** `test_reused_child_pid_does_not_log_unrelated_command_line` proves the log selection and disclosure in process; real PID reuse timing is inferred.

## 2. A lossy start check still passes (high)

**Attacker and steps.** An ordinary process creates enough starts to fill the 512-slot priority lane or the ETW session's 64 buffers during the window. The service's child Start may still be delivered, while other events are dropped. `_check_schema` accepts a matching child independent of `queue_drops`, ETW loss, handler failures, or a failed loss query. `_start` polls and records loss only after the check returns, then can set `state = "on"`.

**Effect.** `etw=on` and a passing schema check can coexist with a known gap in process-event coverage. A later relevant start can be lost while the observer remains apparently enabled. The separate gap counter helps diagnose this, but does not prevent the pass or communicate that the check was inconclusive.

**Lines.** Priority capacity: `etw.py:261-264`; overflow counter: `:326-335`; ETW loss polling: `:530-540`; pass decision: `:801-814`; post-check loss poll and pass state: `:700-718`; session buffer maximum: `:1118-1122`.

**Fix.** Treat any delivery loss, query failure, or dead consumer during the check as an inconclusive check; do not enter `on` until a clean bounded retry succeeds. **Evidence:** `test_child_start_does_not_pass_check_after_event_loss` proves the pass despite `queue_drops=1` in process. The ordinary user's ability to cause the same pressure is inferred from system-wide process starts and the fixed buffers.

## 3. A dead consumer can leave the observer on (high)

**Attacker and steps.** A crash or resource failure makes `ProcessTrace` return after a valid child Start has already entered the check's evidence. `NativeBackend.process` records the return code, and `Collector.lifecycle` reports that the consumer is dead, but neither the check verdict nor `_start` requires the consumer to still be alive.

**Effect.** The service reports `etw=on` even though no thread is consuming subsequent process starts, so ETW scan hints silently stop. The result log includes lifecycle information, but status remains on.

**Lines.** Consumer return recording: `etw.py:1270-1275`; lifecycle observation: `:429-433`; check pass: `:739-751`, `:801-811`; pass state: `:700-718`; aggregator loop's consumer condition: `:439-440`.

**Fix.** Reject a check if the consumer has exited or `ProcessTrace` has returned, and transition an already-on observer to a failed state when the consumer dies later. **Evidence:** `test_dead_consumer_cannot_leave_observer_on` proves the startup pass after a terminated consumer in process; a real ETW failure is inferred.

## 4. Stop deadline does not bound a stalled backend (medium)

**Attacker and steps.** Under a sleep, resource exhaustion, or stuck ETW control call, the backend's synchronous `stop()` stalls. `Collector.stop()` records a six-second deadline but calls `backend.stop()` before either deadline-aware join. `EtwObserver.stop()` calls it synchronously, and `MachineObservers.stop()` cannot proceed to its remaining observers.

**Effect.** Service stop can exceed its ten-second hint indefinitely. The collector's six-second deadline only bounds waits that happen after `backend.stop()` returns.

**Lines.** Synchronous stop and subsequent bounded joins: `etw.py:542-564`; observer call: `:890-905`; native query, disable, STOP and wait: `:1305-1325`; service call path: `agent/sentinel/service/backend.py:723-727`.

**Fix.** Bound the whole stop operation, including native control calls, and prevent a late stop worker from operating on a replacement session. **Evidence:** `test_service_stop_has_a_real_deadline_when_backend_stalls` proves the unbounded call path using a blocked in-process backend. An actual ETW API stall is inferred.

## Other probes

The positive match requires child PID, service parent PID, and interpreter image (`etw.py:739-751`), while raw phase attribution is stamped in the callback (`:320-330`, `:937-941`). An ordinary process with only the same image name does not satisfy it. Filling `_checking` with unrelated process starts also requires the service's parent PID (`:846-854`); this review found no ordinary-user path to that parent identity. A sustained process-start flood can fill the priority queue and make the check fail, which is reported above as a delivery-loss problem rather than a separate schema bypass. A flush-only pass sets `flush_every = 1.0` (`:806-811`), and the aggregator keeps flushing until stop (`:438-453`); this is a persistent overhead but the code alone does not establish a material security effect, so it is not counted as a finding.
