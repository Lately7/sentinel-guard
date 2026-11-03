# RED9 — Process attribution and observation

Pytest was not run in this sandbox. Each finding has a deterministic in-process regression test in `tests/codex/test_red9_process.py`; the expected current failure was checked against the cited branches. All test paths are temporary or simulated. No process is launched and no installed service is contacted.

## 1. Transient image lookup failure permanently hides a live process — medium

- **Attacker model:** A medium-integrity process starts while its image path or metadata briefly cannot be resolved. A short rename or delete window can make `os.stat` fail after the process handle was opened.
- **Steps:** Keep the same `(pid, creation_time)` in two snapshots. Make resolution raise `OSError` once, then succeed. `test_transient_process_image_failure_is_retried` expects the second poll to offer the image; currently it does not.
- **Effect:** The watcher never offers that still-running image to the scan queue. A later journal scan may find the on-disk path, but it cannot recover this process observation.
- **Exact lines:** `procwatch.py:124-145` marks a failed key handled at line 134 and retains it in `_seen` at line 145. `procwatch.py:276-278` performs the vulnerable path `stat` during resolution.
- **Proposed fix:** Keep inaccessible keys eligible for bounded retries while they remain in snapshots. Count the incident once separately from retry attempts.
- **Evidence:** Test-backed code path, pending Claude's pytest run.

## 2. ETW start can be attributed to a different process after PID reuse — medium

- **Attacker model:** A short-lived user process exits before the ETW consumer resolves its start event; Windows reuses its PID for an executable whose first 15 image characters match.
- **Steps:** Deliver a start event with creation time 100 and truncated image name `abcdefghijklmno`. The current snapshot has the same PID with creation time 200 and image `abcdefghijklmnoZ.exe`. `test_etw_start_rejects_reused_pid_even_with_matching_short_name` expects no offer; currently the newer image is offered.
- **Effect:** The old process is missed and the unrelated new image is presented as its executable. Downstream scanning may act on bytes unrelated to the event.
- **Exact lines:** `etw.py:156-166` retains the event timestamp; `etw.py:857-867` resolves using PID alone and accepts a 15-character prefix; `etw.py:908-919` snapshots the *current* PID without comparing its creation time to the event. The sampled watcher does compare creation time at `procwatch.py:269-271`.
- **Proposed fix:** Pass the event's process identity into ETW resolution and reject a current PID whose creation time cannot match the start event. Treat a short image name only as a secondary consistency check.
- **Evidence:** Test-backed code path, pending Claude's pytest run.

## 3. Extended drive path is discarded by ETW — medium

- **Attacker model:** A user process starts from an executable whose image is returned in `\\?\C:\...` form.
- **Steps:** Resolve a matching live process key to an extended drive path. `test_etw_accepts_extended_drive_image_path` expects it to reach the process offer callback; currently resolution raises `OSError`.
- **Effect:** ETW silently misses the process scan hint. A long path may also be outside practical reach of some other path-based observers.
- **Exact lines:** `etw.py:857-864` suppresses resolution errors; `etw.py:908-919` explicitly rejects the extended prefix at lines 916-918. `procwatch.py:272-283` otherwise accepts the queried path up to 32,768 characters.
- **Proposed fix:** Recognize an extended local drive path, preserve a safe scan-capable representation, and validate that it still refers to the same live image. Keep nonlocal device paths rejected unless safely mapped.
- **Evidence:** Test-backed code path, pending Claude's pytest run. The test simulates the API result; the frequency of that result on a given Windows build is inferred.

## 4. Path-only deduplication suppresses a newly replaced running image — medium

- **Attacker model:** A user replaces an executable at a path between two process starts less than ten seconds apart.
- **Steps:** Observe the first image, replace its path with another file containing only the harmless test marker, then observe a new process with a different key and file identity. `test_replaced_image_at_recent_path_gets_new_process_offer` expects two process offers; currently only the first is offered.
- **Effect:** The replacement gets no immediate process-triggered scan. Journal work is deferred until the path is quiet for ten seconds or the maximum quiet window expires; the new process can run in that interval.
- **Exact lines:** `observers.py:30`, `observers.py:126-156` use only normalized path and ten-second age for process deduplication. `observers.py:301-310` has the process target's identity but passes only its path. Journal deferral is at `observers.py:131-144,210-216`.
- **Proposed fix:** Deduplicate process offers by stable file identity plus a change token or content generation, and force a fresh offer when the image at a reused path changes.
- **Evidence:** Test-backed code path, pending Claude's pytest run. The test proves the missing offer, not a completed malicious scan.

## Probes that did not yield separate findings

- The sampled watcher guards PID reuse with `(pid, creation_time)` and rechecks a live handle (`procwatch.py:26-35,269-271`).
- A process that exits before path resolution is counted (`procwatch.py:127-130`; `etw.py:859-862`), but its former image cannot be recovered from a PID-only lookup. Processes living entirely between 500 ms samples are an acknowledged coverage limit (`procwatch.py:3-5,65`).
- ETW's 15-character image-name prefix avoids dropping long names (`etw.py:865-867`), but it does not establish identity, as finding 2 shows.
- Queue saturation is counted and retried while a process remains in snapshots (`procwatch.py:136-145`). ETW queue drops are counted (`etw.py:327-335`), but a departed process cannot be replayed from a later snapshot.
- The USN reader requests only closed-file changes (`usn.py:216-220`). Its journal path can eventually cover some missed process hints, subject to its separate gap and reconciliation behavior.
