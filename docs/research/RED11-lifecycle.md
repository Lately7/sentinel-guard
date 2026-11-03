# RED11: Service lifecycle, crash and recovery

No installed service, live pipe, worker, ETW session, or pytest run was used. The tests use injected in-process objects and the temporary `SENTINEL_HOME` fixture.

## RED11-1 — Partial startup is not unwound (medium)

- **Attacker model:** Crash, full disk, or occupied named pipe during start.
- **Steps:** `ProductService.start()` completes `backend.start()`, then `PipeServer(...)` raises. `ServiceHost.run()` catches that exception and reports `STOPPED` without calling stop.
- **Effect:** Started backend maintenance and observation resources are left until process exit. An ETW session begun before a later startup exception can remain orphaned; recovery depends on the next successful start.
- **Lines:** `agent/sentinel/service/entry.py:29-34`; `agent/sentinel/service/host.py:93-99`; backend startup at `agent/sentinel/service/backend.py:221-231`.
- **Fix:** Make startup transactional: on any exception after backend creation, stop the backend and close the barrier, then re-raise the original error. Preserve the failure status if cleanup also fails.
- **Evidence:** `test_pipe_setup_failure_stops_started_backend` proves the missing cleanup call. ETW persistence is inferred from the asynchronous start and orphan recovery at `backend.py:717-720`, `etw.py:646-658`.

## RED11-2 — Pipe listener death is invisible to SCM (high)

- **Attacker model:** Resource exhaustion or pipe creation failure after startup.
- **Steps:** The `pipe-server` daemon thread returns or fails while `ServiceHost.run()` is waiting solely for `_stop_requested`. `PipeServer.serve_forever()` explicitly stops its own loop when `_new_instance()` raises.
- **Effect:** SCM continues to report `RUNNING`, but new clients cannot reach scanning or protection status. Its failure actions never run because the service process stays alive.
- **Lines:** `agent/sentinel/service/entry.py:33-34`; `agent/sentinel/service/winpipe.py:375-391`; `agent/sentinel/service/host.py:100-102`; failure actions at `agent/sentinel/service/installer.py:269-279`.
- **Fix:** Supervise the listener thread and signal an error stop or terminate the service on unexpected exit. Report `RUNNING` only after the listener is ready and keep its liveness tied to service health.
- **Evidence:** `test_pipe_listener_death_fails_service` proves that a listener exit leaves the fake SCM in `RUNNING`.

## RED11-3 — Observer stop exception bypasses the action barrier (high)

- **Attacker model:** Fault during service stop, such as an ETW shutdown error while an action is in progress.
- **Steps:** `ProductBackend.stop()` calls `observers.stop()` before `barrier.revoke()`. `MachineObservers.stop()` calls `EtwObserver.stop()`, which can propagate an exception from `Collector.stop()` or its native backend. `ServiceHost._close_barrier()` treats the exception as a failed stop and reports `STOPPED`.
- **Effect:** The host exits without first closing the automatic-action barrier; an in-flight privileged action can continue during shutdown instead of being bounded by the stop protocol.
- **Lines:** `agent/sentinel/service/backend.py:233-253,722-726`; `agent/sentinel/service/etw.py:890-905,542-564,1305-1325`; `agent/sentinel/service/host.py:110-120`.
- **Fix:** Put `barrier.revoke(timeout)` in a guaranteed cleanup path before observer cleanup can raise, or catch observer cleanup failure and continue closing the barrier. Preserve an error stop status for the observer failure.
- **Evidence:** `test_observer_stop_failure_still_revokes_barrier` proves the bypass with a one-time observer stop exception. Propagation from a native ETW failure is inferred from the call path.

## RED11-4 — Third crash disables further SCM restart (high)

- **Attacker model:** Repeated crash or kill, including a deterministic startup crash caused by half-written state or failed recovery.
- **Steps:** After the first two crashes SCM applies restart actions at 5 and 30 seconds. The third configured action is `SC_ACTION_NONE`; the reset period is one day. A crash loop within that period exhausts automatic recovery.
- **Effect:** Protection remains stopped until manual intervention even if the underlying condition clears after the third crash.
- **Lines:** `agent/sentinel/service/installer.py:269-279`.
- **Fix:** Configure a bounded longer-delay restart action for subsequent failures, with visible health reporting and logging of the crash loop. Check the read-back configuration as already done at `installer.py:522-532`.
- **Evidence:** `test_failure_actions_keep_restarting_after_third_crash` proves the configured terminal action. Actual SCM scheduling is inferred from Windows service failure-action semantics.

## RED11-5 — Slow startup never advances its SCM checkpoint (medium)

- **Attacker model:** Full disk, long database repair, or slow quarantine reconciliation after an interrupted write.
- **Steps:** `ServiceHost.run()` reports `START_PENDING` once with a ten-second hint and calls `service.start()` synchronously. Backend startup performs database repair, cache pruning, quarantine reconciliation, and observer setup before returning. There is no pending heartbeat during that work.
- **Effect:** A legitimate slow recovery can appear hung to SCM; startup may time out or be killed before recovery completes, leaving protection unavailable. The exact SCM decision is timing dependent.
- **Lines:** `agent/sentinel/service/host.py:91-100`; `agent/sentinel/service/backend.py:221-231`.
- **Fix:** Advance `START_PENDING` checkpoints while startup work is in progress, or split startup into bounded steps with appropriate wait hints. Ensure failed startup still unwinds resources.
- **Evidence:** `test_slow_start_advances_pending_checkpoint` proves no checkpoint advances during a blocked start. SCM timeout behavior is inferred.

## RED11-6 — Immediate restart shows an unfinished quarantine as complete (medium)

- **Attacker model:** Crash or power loss after the action journal and quarantine record are flushed but before the original file is deleted.
- **Steps:** A restart within the 60-second journal grace calls `quarantine.reconcile()` during backend start. It ignores the fresh row. The first maintenance run is after 30 seconds, when the row can still be younger than 60 seconds; the next maintenance interval is ten minutes. Meanwhile `status()` counts the provisional quarantine row as complete.
- **Effect:** The user is told one file is quarantined while the original remains on disk. Recovery can be delayed until the next maintenance run.
- **Lines:** `agent/sentinel/quarantine.py:185-205,258-277,36-38`; `agent/sentinel/service/backend.py:53-54,221-265,346-362`.
- **Fix:** On an exclusive service restart, settle rows known to be from a dead prior process immediately. If another actor may still own a row, report it as pending rather than quarantined and schedule a recovery pass at the grace deadline.
- **Evidence:** `test_restart_settles_recent_crashed_quarantine` proves the false count after a simulated crash row. The ten-minute maximum wait follows the configured maintenance intervals; timing depends on restart time.

## Other probes

Startup stop controls are ignored until `RUNNING` (`host.py:74-85`), consistent with controls accepted only in that state; uninstall retries while start is pending (`installer.py:621-636`). The host advances stop checkpoints when a barrier remains open (`host.py:110-121`). A worker is owned by a kill-on-close job (`worker.py:491-507`, `workerclient.py:149-162`). ETW has a stored-guid orphan cleanup path (`etw.py:646-656`), and first-instance pipe creation rejects a second pipe owner (`winpipe.py:360-373`). These paths did not yield a separate line-tied finding in this round.
