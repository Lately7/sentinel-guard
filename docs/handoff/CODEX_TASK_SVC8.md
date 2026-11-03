# Codex task SVC8: cloud placeholders and the download mark

## Allowed paths

Changed: `agent/sentinel/quarantine.py`, `agent/sentinel/gate_v2/winfile.py`,
`agent/sentinel/gate_v2/identity.py`, `agent/sentinel/gate_v2/scope.py`. New: `tests/test_svc8.py`.
Everything else is read-only.

## Findings

**1. A scan may download every cloud file.** The service runs as LocalSystem. Opening or reading a OneDrive
Files On-Demand placeholder can recall it, or fail. A deep scan or a journal record could pull a user's cloud
library down, or read as a failure. Read the attributes before any content read:
`FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` (0x400000), `FILE_ATTRIBUTE_RECALL_ON_OPEN` (0x40000),
`FILE_ATTRIBUTE_OFFLINE` (0x1000). Such a file is not read and not hydrated, and it is reported through the
existing typed not-checked path, never as clean. `FILE_FLAG_OPEN_NO_RECALL` (0x00100000) exists: say whether
you rely on it and why. Say which of `identity.py` and `scope.py` you changed and why. A file the user
explicitly asked to scan may be treated the same way in this round; the point is that nothing is hydrated
without being asked.

**2. The download mark can be lost silently.** `quarantine.py:107` turns a failed `Zone.Identifier` read into
None, and the restore at line 334 logs a failed write but succeeds. A restored file without its mark is
treated as local by everything downstream. Record whether the mark was preserved in what restore returns, so
a caller can show it. Do not fail the restore over it: the user's file coming back matters more.

**3. A file with no known owner.** `winpipe.file_owner` returns None on failure, and `backend._visible`
decides who sees the event; that policy stays. Only check that `quarantine.py` behaves when an owner lookup
fails during restore. If nothing there depends on it, say so and change nothing.
