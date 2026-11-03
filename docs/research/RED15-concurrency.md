# RED15 — Concurrency across clients

The tests in `tests/codex/test_red15_concurrency.py` are deterministic in-process reproducers. They were read against the implementation and **not run**, as required by the round brief. They use `tmp_path` and the temporary `SENTINEL_HOME` fixture; no service, network, or malware sample is touched.

## High — in-flight enable reopens the barrier after stop

- **Attacker:** a medium-integrity process in the user's session.
- **Steps:** send `enable_protection`; let `ServiceCore.handle` pass its one-time stopping check, pause before backend execution, then stop the service and resume the request. The test coordinates this with events.
- **Effect:** `ProductBackend.stop` revokes the action barrier and closes the worker, but the accepted request subsequently calls `barrier.resume()`. The service can report protection enabled during shutdown; any still-running scan reaching `_finish` can enter the action barrier after stop.
- **Lines:** `agent/sentinel/service/core.py:118-129,253-254`; `agent/sentinel/service/backend.py:233-253,501-515,541-545,588-592`; `agent/sentinel/gate_v2/actions.py:34-63`.
- **Fix:** serialize the stop transition with enable, reject enable after backend stop starts, and ensure an in-flight enable cannot resume a stopped barrier.
- **Evidence:** proven by `test_enable_in_flight_cannot_reopen_barrier_after_stop` for the reopened barrier; the later action is inferred from `_finish`.

## High — timed-out off approval records protection as off while an action runs

- **Attacker:** a concurrent malicious file scan or an action stalled by an on-disk condition; the administrator approves off while that action runs.
- **Steps:** hold one action lease, execute `disable_protection` with an expired action wait, then inspect persisted `OFF_META` before the lease exits.
- **Effect:** `revoke` returns `False`, but the backend writes the off flag and the “protection off” event anyway. The approved state is shown and persisted while a quarantine action can still be executing.
- **Lines:** `agent/sentinel/gate_v2/actions.py:34-61`; `agent/sentinel/service/backend.py:541-545,623-629`; `agent/sentinel/db.py:361-366`.
- **Fix:** publish and persist off only after the action count reaches zero; on timeout, report a pending/failed transition and complete it only once the barrier is closed.
- **Evidence:** proven by `test_disable_timeout_does_not_publish_off_while_action_runs` for the off flag during an action lease. Quarantine is the production holder of the lease at `backend.py:541-542`.

## Medium — one medium client consumes the tray's scan quota

- **Attacker:** another medium-integrity process under the same SID and session as the tray.
- **Steps:** enqueue 64 scans that remain queued; then request a tray scan of a readable file. The repro uses harmless paths and a fake queued backend.
- **Effect:** the tray gets `BUSY` because the outstanding-job counter belongs to `(SID, session)`, not to the client connection. Repeating the hostile submissions can keep on-demand scans unavailable.
- **Lines:** `agent/sentinel/service/authz.py:31-33`; `agent/sentinel/service/core.py:192-213`; `agent/sentinel/service/backend.py:412-421`.
- **Fix:** retain the global bound but add per-connection admission and fair queuing or a reserved share for trusted UI work; a same-token process must not monopolize the user's entire quota.
- **Evidence:** proven by `test_hostile_client_cannot_fill_tray_scan_quota` for admission denial; sustained starvation is inferred.

## Medium — one medium client consumes the tray's request bucket

- **Attacker:** another medium-integrity process under the same SID and session as the tray.
- **Steps:** send 60 valid status requests at a fixed clock instant, then send the tray's status request.
- **Effect:** the tray gets `RATE_LIMITED`; continuous traffic at the 20-per-second refill rate can keep status and other requests unavailable.
- **Lines:** `agent/sentinel/service/authz.py:31-33`; `agent/sentinel/service/core.py:54-55,118-123,154-167`.
- **Fix:** allocate fair per-connection buckets with a bounded aggregate budget, and keep enough capacity for service status and job-result reads.
- **Evidence:** proven by `test_hostile_client_cannot_rate_limit_tray_status` for the immediate denial; sustained starvation is inferred.

## Other paths reviewed

The asked and observed lanes are separate (`backend.py:203-205`), but both eventually call the same `_run` and action path (`backend.py:431-437,501-545`). `WorkerSession.call` serializes worker access with a deadline-aware lock (`workerclient.py:200-210,259-272`). Quarantine claims a file key before acting and compares copied bytes with the measured hash (`quarantine.py:170-179,193-205`), so I did not report a same-file wrong-target race. Database transactions hold a reentrant lock while writing (`db.py:325-357`); I found no concrete backend/database/worker lock cycle. Stop cancels jobs and closes the worker only once the barrier is closed (`backend.py:233-253`); the two stop findings above are the concrete failures found at that boundary.
