# Codex task SVC3B: second round on the observer, and the journal reader

Your uncommitted change from SVC3 is in this worktree; continue from it.

## Allowed paths

Changed: `agent/sentinel/service/observers.py`, `agent/sentinel/service/usn.py`,
`tests/test_svc3.py`, `tests/test_service_observers.py`. Everything else is read-only.

## Findings

**1. A process hint loses the free slot.** `tick_processes()` retries refused paths before polling, so
with one permit free an old journal path takes it, and a newly seen running program finds the queue full.
Poll first, offer what is new, then retry.

**2. A refused file is scanned inside a new quiet window.** A journal offer refused at 10 s can be retried
by the process thread at 10.2 s after the file was rewritten at 10.1 s, before the next journal tick reads
that write, and the scan can block the writer. Retry journal paths only from the journal tick, after it
has read the batch. Process hints may retry from either.

**3. Two older tests expect the old behaviour.** `test_only_files_that_can_run_are_offered_and_only_once`
and `test_a_burst_past_the_queue_is_counted` call one tick and expect an offer or refusal on it. Update them
to the quiet window, keeping what each one protects. Do not weaken them.

**4. Add `Observers.owe()`,** which sets `_owed`. Another round calls it. Keep it one line.

**5. A file whose lookup failed is lost.** `usn.py:220` and `:298`: `unresolved` counts records whose path
lookup returned None or raised `OSError`, and a file that still exists can land there when `OpenFileById`
fails, with the cursor already past it and nobody told. On this machine `unresolved` is 86,988 against
73,658 `records`, though most are probably files already deleted. Distinguish a vanished file, which is
fine, from a lookup that failed, in a new counter `lookup_failed`, reported by `report()`. Keep a bounded
list of failed file references and try them again on the next tick. When that list overflows, or an entry
has failed three times, set `_owed`. A reconciliation is the existing backstop.

**6. One 1 MiB batch per tick can fall behind.** `usn.py:189`: only one batch is read per 5 s tick, so a
sustained burst can let the journal wrap, which loses records. Read bounded batches until caught up, with
a limit of about 16 batches per tick so that a journal storm cannot hold the thread. Save the cursor after
each batch, as now, so that a crash loses nothing already read.
