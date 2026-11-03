# Codex task DOCS2: records of rounds SVC11 to SVC16

Claude reviews this. Do not commit. Use only the facts below, `git log` and the code. Never record a result not listed
here.

## Allowed paths

`REVIEWS.md`, `TASKS.md`, `docs/ROADMAP.md`, `docs/handoff/PLAN.md`, `docs/handoff/NEXT_SESSION.md`, `README.md`. Keep each
file's voice and language. Plain sentences, no marketing.

## Facts

The owner chose to stay in user mode as LocalSystem, with no driver, and to use ETW. That answers question 4 in PLAN §6:
ETW beside the sampler. Record it as decided by the owner on 2026-11-03. Kernel-level blocking is out of scope for now,
so the limit stays: the product sees a file or process after it appears and does not stop it before it runs.

Tests: pytest 1039 passed, 10 skipped, 1 xfailed, twice in a row; extension 40 passed. Helium e2e was not rerun, and now
stops on a machine with the service installed unless given `--with-service`.

Rounds, all merged; take commit ids from `git log`. SVC11 and SVC11B: ETW, checked live. SVC12 and SVC12B: shadow scoring.
SVC13: `sentinel service status`. SVC14: the fixed-drive walk. SVC15: the worker's self-diagnosis. SVC16: approvals, from
reviews R6 and R8. Claude wired ETW, scoring and the walk into the service.

For `REVIEWS.md`, add a section `### Seventh round: ETW, scoring and approvals` with a table of what review caught:

* SVC11: the process event holds a short name, not a path, so ETW would never have come on; the check held up the start;
  any dropped event failed it; every file read called into Python. Fixed in SVC11B, with a rate guard.
* SVC12: any event with no known name or process wiped the state, so 30 days would have read as clean with the scorer
  never filling. A disk rewrite per document event. Fixed in SVC12B. `would_have_suspended` needs a canary, so its zero
  is not a result, and the report says so.
* SVC15: the restart check would have cut the diagnosis off, so `tools/install_service.cmd` now waits before it.
* SVC14: a finished walk answered done to every later call, clearing new debts with nothing looked at.
* SVC16: the elevated helper's `consent.log` in the state tree could have failed the ownership check at the next start.
  The helper reports through its exit code alone.
* Wiring: file events name files by device, and process events did not reach the scorer.
* R6's concern about the pipe's integrity label was refuted by measurement: an ordinary client has talked to the real
  service.
* R8's claim that a local clean after a service unknown is false was not accepted: that scan ran real engines.

Not verified on a real session: all of ETW. The process and file payload layouts come from documentation and
may differ; the check logs what it saw. The 30 days have not started: they start when ETW comes on.

`TASKS.md`: Codex log rows for SVC11, SVC11B, SVC12, SVC12B, SVC13, SVC14, SVC15, SVC16, R6, R8, DOCS2, one line each.

`docs/ROADMAP.md`: the test line gets the numbers above. Mark in step 10's wording that ETW and shadow scoring are wired but
unverified, and that canaries wait for owner question 11. Do not mark anything as done that has not run.

`docs/handoff/PLAN.md` §0a and `NEXT_SESSION.md`, top update block: the next step is the owner opening
`tools\install_service.cmd`. What the log will show: the `worker diagnosis:` lines name which step fails, and `etw check:`
lines show the real payloads if ETW stayed off. `sentinel service status` works from an ordinary window.

`README.md`: add `sentinel service status` to the commands, and one sentence in the service section that ETW is used when its
check passes and that the service works without it.
