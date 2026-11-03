# Codex task SVC1: a service whose worker is down, and what it tells people

## Allowed paths

Changed: `agent/sentinel/service/workerclient.py`, `agent/sentinel/service/backend.py`,
`agent/sentinel/service/bridge.py`, `agent/sentinel/nativehost.py`, `agent/sentinel/overview_ui.py`.
New: `tests/test_svc1.py`. Everything else is read-only, including `service/worker.py`, `installer.py`,
`verify.py`, `entry.py`, `workermain.py`, which Claude is changing now.

## Findings

**1. Native host takes the service's unknown as final.** `nativehost.py:158-164`: once the service
answers, `on_scan_download` returns its result and never reaches the local scan at 165-169. With the
worker down the answer is label `unknown`, so a browser download gets no local check. Fix only the
return at line 163: an `unknown` answer falls through to the existing local scan. A failed job must stay
the retryable error it is today (lines 160-162).

**2. A failed worker is launched again for every stage of every scan.** `workerclient.py`, `call()`:
each observed file is scanned 5 times, each scan tries 4 stages, each stage tries a start, so one file
makes 20 launches and 20 log lines. After a failed start, `WorkerSession.call` refuses for about 60 s
without launching, then tries again, so a worker that can come back does. Log only when the failure
text changes. Also set `last_failure` from the code of any `WorkerFailure` raised during a start, not
only from an `OSError` or `_died`. A successful start clears it. Replacing the session clears the wait.

**3. Retries and per-file events while the worker is down.** `backend.py`: while
`scanner.isolation.failure()` is set, do not retry observed files or add a per-file event; count them,
and show the count in `status` as `worker_down_skipped`. In `_gave_up`, word the event by cause when
that failure is set, not as a fault of the file. Prune events in `_maintain` next to `prune_cache`, and
add what that needs only if `db.py` already allows it; if it needs a change in `db.py`, skip this part
and say so.

**4. A rule update right after a start rescans nothing.** `backend.py:281-284`: `_rule_generation`
starts as None, so an update in the first maintenance pass becomes the baseline. Remove the None guard,
since `signatures_changed` compares each item's stored generation. Line 471 remembers only reason
`download`: update the stored generation after a rescan too, so a restart does not repeat them.

**5. A file that can never be covered is retried as if transient.** `backend.py:383`: a ZIP over 64 MiB
is always `INCOMPLETE_COVERAGE`, yet is retried and then blamed on the file. Retry only for `IN_USE`,
`CHANGED`, timeouts and engine failures, read from `reason_codes`, not for `INCOMPLETE_COVERAGE`. Its
event says it could not be fully checked, not that it stayed busy.

**6. The tray drops a hash hit the service cannot know.** `bridge.py:146-161`, `_left_to_us`: "the
service ran core" counts as an answer even when the service has no such hash. Each side reads the
abuse.ch key from its own settings. A `KNOWN_BAD_HASH` hit stays left to this process unless the service
reports the same evidence.

**7. Nothing but `verify` shows that the worker is down.** `overview_ui.py:32`, `protection_state` looks
at the tray's own watcher, feeds, ClamAV and the extension, never at `lease.status()`. Read
`worker_failure` from it and show the attention state, with Vietnamese text that says scanning is not
working and what was being protected. Nothing here may block the UI thread on a dead pipe: use whatever
the existing `lease` calls already do about that.
