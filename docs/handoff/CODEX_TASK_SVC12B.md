# Codex task SVC12B: second round on the shadow observer

Your uncommitted change from SVC12 is in this worktree; continue from it. Same allowed paths: `service/burst.py`,
`service/shadow.py`, `tests/test_svc12.py`. Findings from review. All of them would have made the 30 days of
observation look clean while measuring nothing.

**1. An unattributed event must not wipe the state.** `_gap` replaces the scorer and clears `_names` and `_processes`.
It is called for `unattributed_file` and `unattributed_process`. On a real machine, files opened before the session
started never get a name event, and processes started before it never get a start event, so these arrive all the
time: each one wipes everything, the scorer never collects a burst, and `_in_gap` stays true so `gaps` barely moves.
A gap means coverage was lost: collector loss, downtime, a malformed event. Unattributed means this one event could
not be used. Count `unattributed_file` and `unattributed_process` in `report()`, change nothing else, and return.
`report()` also gives the share of read and write events that were usable, since a low share means the numbers below
it say little.

**2. Processes that were already running.** Those have no `process_start`, so a long-running program can never score.
When a read or write comes from a pid with no entry, make one on the spot, with the image from `image_name` and a
creation time that marks it as not seen starting, and let it score. Count these. A pid reused later must not
inherit the old entry: a `process_start` replaces it, and `process_stop` removes it.

**3. Capacity must evict, not reset.** `name_capacity` and `process_capacity` wipe everything. Evict the oldest entry and
count it. `_names` entries past `NAME_TTL_SECONDS` must also go, so a long quiet stretch cannot fill it.

**4. Log what matters.** `_emit` writes a line for every document event, including `insufficient_evidence`, and once
at the size bound each line rewrites and fsyncs up to 256 KiB. Write a line only for an alert or a change of state.
Add a counter of decisions not logged. A burst of a thousand document events must not cost a thousand disk rewrites:
a test measures how many times the writer is called for one.

**5. Say what the numbers cannot show.** `would_have_suspended` needs a canary, and nothing supplies one, so it stays 0
whatever happens. Keep it, and add to `report()` a field that says so, so that a reader of a 30-day report does not
take 0 for a result. `provisional_alerts` is the number that tells something.

Each finding needs a test that fails before it. Add one that feeds a realistic mix: 95 % of events on files and
processes with no prior name or start event, 5 % a real burst on documents from one process, and checks that the burst
is still found.
