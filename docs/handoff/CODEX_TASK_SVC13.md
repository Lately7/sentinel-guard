# Codex task SVC13: `sentinel service status`

Only an administrator can read `service.log`, and `status` over the pipe needs a script today. The owner should
be able to see how the service is doing from an ordinary window.

## Allowed paths

Changed: `agent/sentinel/__main__.py`. New: `tests/test_svc13.py`. Everything else is read-only.

## Build

Add `status` to the actions of `sentinel service`. It needs no elevation and uses `ServiceClient`.

* Not installed, stopped or unreachable are three different answers, each in plain Vietnamese. Use
  `installer.registered_version` and `WindowsScm.binary`, and for stopped versus running read the service state
  without needing rights beyond what the service's own security descriptor grants to interactive users.
* When it answers, show in Vietnamese: version; whether real-time is on; whether scanning works, from
  `worker_failure`, with the failure text as it is; quarantined count; and from `observation`: records,
  `refused_paths`, `lookup_failed`, `journal_lag_bytes`, `largest_gap`, `slept_seconds`, and `etw` if the key is there.
  A key that is missing prints as not reported, never as zero: an older installed build lacks several of these.
* The first line is the answer to "does it protect me now": scanning works, or it does not and why. Service
  running with a dead worker must not read as fine.
* `--json` prints the reply as it came. Exit code 0 when scanning works, 1 when it does not, 2 when the service is
  not reachable.
* The installed build may be older than this checkout: reply keys are read with care, and an unknown key is ignored.
