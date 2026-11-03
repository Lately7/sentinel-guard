# Codex task SVC2: feeds and rules

## Allowed paths

Changed: `agent/sentinel/feeds.py`, `agent/sentinel/yarafeed.py`, `agent/sentinel/gate_v2/rules.py`.
New: `tests/test_svc2.py`. Everything else is read-only. `service/workerclient.py` is being changed by
another round: call it, do not edit it.

## Findings

**1. Offline, every pass rebuilds the whole snapshot.** `feeds.py:292`: when every fetch fails,
`_update_all` still publishes a snapshot of carried-over rows, and publishing bumps the generation.
`is_due` stays true because no row is ok, so `service/backend.py:251` repeats this every 600 s. Measured
with a 75.6 MB snapshot of 543,020 hosts: 3 passes of 7.5 to 13.2 s, the generation and gate id changed
each time, which invalidates every cached decision, and it was still due. When no source reports ok,
discard the builder and return without publishing. Record an attempt time so `is_due` retries about
hourly, as `engine_update_due` does. A partial success still publishes as today.

**2. A rule package within the size limit can kill a working worker, and stays.** `yarafeed.py:84`:
`update` accepts up to 64 MiB and validates by compiling in the parent, which has no memory cap, then
replaces the rule file. The worker has a 512 MiB job cap. Measured through the real launch path with
synthetic rules: 5.5 MB peaked at 135 MB, 20 MB at 457 MB, 30 MB died at init with `0xC0000409`. Once
replaced, every scan is unknown for good. Before `os.replace`, start a trial `WorkerSession` with the
new source under the same cap, through an injected parameter whose default does the real thing; keep the
old file on failure and return an `error:` string as the other failures do. The session must be closed
on every path. Bundled and user rules are read-only here, but they count toward the trial, since the
worker loads them all: use the same sources the scanner would.

**3. A file read completely is called partial.** `gate_v2/rules.py:315`: non-ZIP files of 64 to 72 MiB
are read completely by head plus tail, yet the adapter reports PARTIAL, and `gate_v2/policy.py:167-171`
counts that as incomplete, so such a file is unknown for ever. Derive partial from `reader.ranges` after
the tail read. Do not touch the ZIP path at line 314: a partial walk of a large ZIP really is partial.
