# Codex task SVC5: the next elevated run must name its own failure

The installed worker failed on every attempt, and nothing recorded why. Four attempts took 49 ms in
all, too fast for a Python import fault, which measures about 300 ms; so it most likely failed in a
launch call or just after. The owner has limited elevated runs, so the next one must say what happened.

## Allowed paths

Changed: `agent/sentinel/service/worker.py`, `agent/sentinel/service/workerclient.py`,
`tests/test_service_worker.py`. New: `tests/test_svc5.py`. Everything else is read-only.

## Findings

**1. `Worker.kill` does not kill a busy worker.** `worker.py`, `kill()` closes stdin and stdout first,
and only then closes the job handle. `WorkerSession._pump` sits in a blocking read on that stdout, and
closing the fd from another thread waits for that read, so `CloseHandle(job)` is not reached while the
worker is alive and silent. Measured: `kill()` took 14 s against a 15 s sleep and returned only when the
child ended by itself. Close the job and thread handles first, so the worker dies and the pump gets end
of file. Add a blocked reader thread to `test_kill_ends_a_busy_worker_promptly`.

**2. stderr shares the frame pipe, so any text kills a healthy worker.** `launch` sets `hStdError` to
`child_out_w`, the pipe carrying reply frames. `read_frame` takes the first four bytes of any text as a
length: `b'Fail'` is about 1.8 GB, so it raises `TOO_LARGE` and the worker is reported dead. Python does
print to stderr at start under a restricted token. Give the child its own stderr pipe: a third handle in
the inheritance list, drained by a small daemon thread in the parent so the child cannot block on it.
Keep the last 2 KiB in `Worker`, with a method to read it.

**3. The worker's own words are thrown away.** With finding 2 in place, when a start fails, write that
tail to the log with the failure. No file has reached the worker at that point, so it cannot hold file
content. `status` keeps only the short code; the tail goes to the log alone. After a start has succeeded
the tail may hold paths or content from a parse fault: do not log it then.

**4. `last_failure` is blank or stale for some start failures.** `workerclient.py`, `call()`. Measured
with a worker that refused `init` and a start past its deadline. Clear `last_failure` before `_start`;
in the except block use `str(e)` for an `OSError`, and otherwise `self.last_failure or e.code`. A launch
call that fails must keep its name and Windows code in the text, as `_fail` builds it. Exit codes are
read before the job is closed: check that this still holds after finding 1.

**5. An unexpected exception must not disappear.** `call()` catches `OSError` and `WorkerFailure` around
`_start`. Anything else there, such as a `ctypes.ArgumentError` from a bad argument, escapes with no
`last_failure`. Catch `Exception` for the record, set `last_failure` to its type name and text, log it,
and raise the usual `WORKER_UNAVAILABLE`.
