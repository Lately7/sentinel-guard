# Codex task SVC6: stopping, catching up, and what a repair really did

## Allowed paths

Changed: `agent/sentinel/service/backend.py`, `agent/sentinel/service/repair.py`. New: `tests/test_svc6.py`.
Everything else is read-only. Another round is adding `Observers.owe()` in `observers.py`, which sets
`_owed`: call it, do not edit that file. In tests, use a stand-in with that method.

## Findings

**1. A service stop is not bounded while an observed scan is in a worker call.** `backend.py`, `stop()`
cancels only `self._jobs`, which holds asked scans; `observe()` submits to the observed lane without
registering there, so a journal, process or reconcile scan is never cancelled. `stop` then calls
`isolation.close()`, and `WorkerSession.close` takes `_lock` with no timeout, while `call()` holds it for
up to the 120 s deadline, so `host.py` `_close_barrier` cannot time out. Cancel the jobs running in both
lanes (`_observed_lane.running`, `_asked_lane.running`, entry 0) before `isolation.close()`; `_send` sees a
cancel within 50 ms. Check the entry shape first. The action barrier's order must not change: no action
may start after `stop` has closed it.

**2. Files skipped while the worker was down are lost.** `_after_observed` counts them in
`_worker_down_skipped` and drops them, and when the worker returns nothing catches up. When the failure
clears and something was skipped since the last catch-up, call `self.observers.owe()` once, so a
reconciliation walks them. Check this from `_watch`. `observers` may be None. Do not reconcile while the
worker is still down, and do not loop: the worker failing again later starts a new count.

**3. A denied process is called gone.** `repair.py`, `stop_process` returns False when `OpenProcess` is
denied, which reads as "the process is not there". Distinguish a vanished process from
`ERROR_ACCESS_DENIED`, and raise the existing `REFUSED_PROCESS` for the latter. The file must not be
quarantined as if the process had stopped. The service token has no SeDebugPrivilege.

**4. A repair claims more than it does.** `repair.py`: scope lists scheduled tasks and WMI consumers, but
a repair removes only Run values, so a file can be quarantined with that persistence left. Removing them
is out of scope. What the plan shows the user, and what the result reports, must say which were found and
left in place, in Vietnamese. A `Run` value on a hive that failed to open stays reported as left.
