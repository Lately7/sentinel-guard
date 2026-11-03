# Codex task SVC3: what the journal observer offers, and when

## Allowed paths

Changed: `agent/sentinel/service/observers.py`. New: `tests/test_svc3.py`. Everything else is read-only;
`service/backend.py` is being changed by another round, so `submit`, `reconcile` and the `report()` keys
already read elsewhere keep their meaning.

## Findings

**1. A package install fills the observed queue, and what is dropped is never scanned.** `observers.py:96-115`:
one observed lane drains about 6.6 files/s, so 2,048 permits are about 309 s of work. Normal load is
0.44 to 1.04 files/s. `pylive-inspector/node_modules` alone holds 4,516 files with risky suffixes, so one
install can fill the queue, and `_offer` then only counts `queue_full` and sets `_owed`, which causes one
hourly reconciliation that may not reach that file. Keep a bounded list of refused paths, like `_again`,
and offer them again on later ticks while the queue has room. Refused process hints go first: a program
that is running matters more than a file that was written. Past the bound, `_owed` stands as it does
today. Report the list's length in `report()` under a new key.

**2. The scan holds a deny-write handle on every risky file on every fixed drive, within 5 s of its
close.** `gate_v2/content.py:35` shares read and delete but not write, for the whole scan, so a program
that rewrites its file meets a sharing violation. Measured: open for write and truncate failed while it
was held. The window is about 150 ms for a small file, and much longer for a large one. For journal
offers, wait until the file has been quiet for `RECENT_SECONDS` before the first offer, reusing the
`_again` logic, so a rewrite loop is scanned once it settles. A file still being written keeps moving its
own quiet time forward, and a bound applies: a file written for longer than about 60 s is offered anyway,
so that a process cannot keep a file from ever being scanned by touching it. Process hints are not
delayed, and neither is anything marked `fresh`. A file under this wait must not be lost when it leaves
the bounded map: it falls to `_owed` as the existing overflow does.
