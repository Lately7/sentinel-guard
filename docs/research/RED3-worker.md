# RED3 — worker isolation and protocol

These are source-backed, in-process reproductions. Per the round rules, pytest was **not run**; Claude must execute the tests. The fake workers model a parser-compromised or nonresponsive low-integrity worker. No parser exploit is claimed.

FIX5 triage dropped `test_worker_clean_claim_requires_proof_of_stage_read`: the worker is the analyzer, and the parent contract does not promise proof that a compromised worker read or evaluated the file.

## High — unbounded valid reply flood escapes the job memory cap

- **Attacker:** a downloaded file that gains control of the scan worker through a parser flaw (inferred prerequisite).
- **Steps:** after one legitimate reply, have the still-running worker send many valid, small unsolicited reply frames while the session is idle. Each frame is under the 1 MiB limit. The reader thread keeps appending them without a consumer.
- **Effect:** the parent service accumulates an unbounded `queue.Queue`, outside the worker's 512 MiB job process limit. This can exhaust service memory and interrupt protection.
- **Lines:** `workerclient.py:103` creates an unbounded queue; `:139-145` reads and enqueues frames without a pending-request or queue-depth limit; `:183-198` consumes only one frame per request. `protocol.py:54-73` bounds each frame, not the stream. `worker.py:428-444` caps the worker process only.
- **Fix:** permit at most one outstanding reply, reject unsolicited or excess frames, and terminate the worker when that limit is exceeded. Bound any interthread queue.
- **Evidence:** `test_unsolicited_worker_frames_have_bounded_parent_buffer` supplies 1,000 valid frames to `_pump` in process and asserts a small queue bound. The test is unrun; the growth follows directly from the cited code.

## High — worker can certify bytes it never checked as clean

- **Attacker:** a downloaded file that controls its worker through a parser flaw (inferred prerequisite).
- **Steps:** the service measures a harmless on-disk marker file that the test-only JSON rule detects. A fake worker receives the duplicated handle but does not read it. It sends a correctly shaped `COMPLETED`/`CLEAN` `EngineResult` with full, verified coverage and the parent-provided identity.
- **Effect:** `WorkerAdapter` accepts the claim, the policy can return trusted clean, and the scanner can put that negative decision in the long-lived cache. The contract verifies the shape and identity fields, not that the worker read the claimed ranges.
- **Lines:** `workerclient.py:335-368` sends the handle and accepts an identity-matching result; `workermain.py:70-83` is where an honest worker reads the handle; `contract.py:243-245,310-327` checks consistency of claimed coverage and status; `policy.py:172-182,200-217` turns that claim into trusted clean; `cache.py:54-69` makes trusted clean a long cache entry.
- **Fix:** make negative coverage accountable outside the worker: broker reads through the parent and record actual ranges, or require an independent trusted negative check before granting trusted clean and long caching. Treat unaccounted worker-only negatives as unknown.
- **Evidence:** `test_worker_clean_claim_requires_proof_of_stage_read` compares the real in-process JSON rule hit with a fake clean reply for the same measured file. The test is unrun; the ability to induce such a reply from a real file is inferred.

## Medium — synchronous worker pipe write ignores the scan deadline

- **Attacker:** a nonresponsive worker after a crafted file triggers a parser hang, or a worker that stops reading its stdin.
- **Steps:** block the worker's stdin write. `_send` waits inside `write_frame` before it reaches the deadline and cancellation polling loop.
- **Effect:** a scan thread can remain occupied past its deadline, and the session lock prevents other calls from using that worker. A large 128 MiB initialization frame raises the chance of a blocked write.
- **Lines:** `workerclient.py:166-185` performs a synchronous write before deadline checks; `:259-272` holds the session lock across it; `protocol.py:35-41` writes and flushes synchronously; `protocol.py:17-19` permits a 128 MiB init frame.
- **Fix:** perform pipe writes with cancellable/overlapped I/O or a bounded writer whose timeout kills the worker and releases the call. Apply the caller's deadline to startup and write phases.
- **Evidence:** `test_worker_pipe_write_obeys_scan_deadline` uses a fake blocked stdin and checks that the call finishes with a timeout before the write is released. The test is unrun; the blocking path is direct from the cited code.

## Other probes

The reader rejects a single oversized or malformed-JSON reply, and a mid-frame exit becomes a worker failure (`protocol.py:54-73`, `workerclient.py:139-158`). An out-of-order reply kills the worker (`workerclient.py:189-191`). Stderr is drained into a 2 KiB tail (`worker.py:467-482`). The launch lists only three inherited pipe handles, assigns the suspended child to a one-process memory-limited job, and uses a restricted low-integrity token (`worker.py:319-374,428-444,569-598`). The service worker is assigned a private station and desktop (`worker.py:377-425,578-579`). The worker environment contains only SystemRoot and System32 PATH; no explicit scratch directory is passed (`worker.py:447-457,585-589`). These paths did not yield another source-backed finding in this round.
