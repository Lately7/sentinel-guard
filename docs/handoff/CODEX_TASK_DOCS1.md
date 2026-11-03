# Codex task DOCS1: bring the records up to date

Claude reviews this. Do not commit. Use only the facts below and `git log`, `git show` and the code. **Never record
a result that is not listed here**: where a number is unknown, write `PYTEST_RESULT` and Claude fills it in.

## Allowed paths

`REVIEWS.md`, `TASKS.md`, `docs/ROADMAP.md`, `docs/handoff/PLAN.md`, `docs/handoff/NEXT_SESSION.md`. Nothing else.
PLAN and ROADMAP are in Vietnamese, the others in English; keep each file's voice, and match the tables already
there. Plain sentences, no marketing, no bold scattered about.

## Facts

First real install, 2026-11-03, run through `tools/install_service.cmd`: 13 PASS, 1 FAIL, 2 SKIP. The service ran as
LocalSystem for the first time. Passed for real: service_config, sid_type, privileges, failure_actions,
users_cannot_stop, runtime_hashes, state_acl, isolated_imports, pipe_owner, refuses_unknown_op, observers,
clean_stop_and_start. SKIP: medium_token_cannot_approve, remote_client_refused. FAIL: worker_scan: all four worker
stages unavailable, 49 ms in total, every scan unknown. The cause is still not known. `a9e9379` calls the shared
window station the suspected cause; later measurement says that is unlikely, since a fault in user32 takes over
1,100 ms for four attempts. Do not state a cause. After hours of running, the service showed 73,658 records,
86,988 unresolved, 0 failed polls, largest gap 10,667 s, cause not established.

Add to `REVIEWS.md`, after the fifth round, a section `### Sixth round: what the first real install showed`, with one
table per kind: faults fixed, by round, from `git log` of merges `svc1` to `svc6`, and one row each for:

* Refused from a Codex brief: treating a 64-72 MiB file read as head plus tail as complete. They are two buffers, so
  no rule sees across the seam, and a clean there would be false. Pinned by a test.
* Caught in review of SVC3B: a deleted file's id answers error 87 on NTFS (measured), which the round's list lacked,
  so every deleted file would have counted as a failed lookup and forced a reconciliation each hour for good. Also
  the round dropped de-duplication of process hints.
* Caught by a test at merge of SVC2: an offline pass must still publish a new popular list.
* Refuted by review: Defender names cannot reach automatic quarantine on real MpCmdRun output.
* A delete still pending answers error 5 and is retried once (measured).

Left, say so plainly: rescans ran on a native-host unknown three times for one download at worst; a scan that
reconciles after a lost journal is limited to the smart scope; short-lived processes between samples are not seen;
restored files take the destination's ACL and the service as owner; repairs leave scheduled tasks and WMI consumers
in place, and say so.

`TASKS.md`: add rows to the Codex log for rounds SVC1 to SVC6, and SVC3B, read-only reviews R1 to R5, one line each.

`docs/ROADMAP.md`: replace the test line's pytest numbers with `PYTEST_RESULT`.

`docs/handoff/PLAN.md` §0a and `docs/handoff/NEXT_SESSION.md`, top update block: the service is installed on the
owner's machine and running with a worker that does not start, so it detects nothing; the tray and native host fall
back to their own scans when the service answers unknown, once the next install lands. The next step is the owner
running `tools/install_service.cmd` themself, because Claude must not start a UAC prompt: it did once, against §7,
and that is recorded. The result is in `%TEMP%\sentinel-install.log`, and `worker_failure` in `status` names the
cause. Codex is back in use: rounds run in `..\sentinel-guard-svcN` worktrees, as in NEXT_SESSION §4.
