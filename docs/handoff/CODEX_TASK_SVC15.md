# Codex task SVC15: one elevated run must pin down why the worker fails

In the installed service every worker attempt failed in about 10 ms, and the cause is unknown. It can be measured
only inside the service, as LocalSystem in Session 0, and each attempt costs the owner a UAC click. So on its first
failed start the service should try a small set of variants itself and write each result to its log, so that one
run tells us which step is the problem.

## Allowed paths

Changed: `agent/sentinel/service/worker.py`, `agent/sentinel/service/workerclient.py`. New: `tests/test_svc15.py`.
Everything else is read-only.

## Build

`worker.diagnose(python: str, cwd: str, service_sid: str) -> list[dict[str, str]]`, and a call from `WorkerSession`
once per process, after the first failed start in the installed service only (`active_version()` is not None).

* Each variant runs `python -I -B -c "pass"`, then, if that passed, `-c "import ctypes"`. **Never a scan, never a
  file, never the real worker module.** Nothing in the variants may read or act on anything but the interpreter.
* Variants vary one thing at a time from the real launch: the private desktop or the service's own; with the
  restricting SIDs or without; low integrity or the parent's; DETACHED_PROCESS or CREATE_NO_WINDOW; the token's
  default DACL as it comes, or one granting the restricting SIDs; in the Job Object or not. Keep it to about 8.
* Variants weaker than the real launch exist only to learn what fails: each runs in a job with kill-on-close and
  a 5 s limit, and none is ever used for scanning. The real launch keeps its restrictions whatever the results say.
  A test checks that nothing outside `diagnose` calls the weaker paths.
* Each result records: the variant, the call that failed with its Windows error, or the exit code, and the last
  2 KiB of stderr. Also record, once: the token's user, groups and privileges by name, the session id, the desktop
  and station names, and `sys.executable`.
* Log it all at WARNING under one prefix, `worker diagnosis:`, so the tail of `service.log` shows it. `tools/install_service.cmd`
  prints the last 40 lines, and the diagnosis may be longer: fit each result on one line and keep the total under
  30 lines, the summary last.
* It runs on its own daemon thread and must never delay or fail a scan, a stop or the service. Any exception inside
  ends the diagnosis with one log line. A process stuck past its limit is killed by closing its job.
* Split the launch so that the variants share `launch`'s code rather than copy it, with parameters defaulting to
  today's behaviour, so the real path stays exactly as it is, and existing tests pass unchanged.
