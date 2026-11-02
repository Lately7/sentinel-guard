# Codex task — edge-case test round against Gate v2 and the agent

The owner asked for the nastiest edge cases in this project's own code. You write tests only.
Claude runs them; a failing test that shows a real defect is a success. Stay on the branch this
worktree is on; do not commit.

**Sandbox note:** you cannot run pytest in this sandbox (temp folder denied). That is *not* a
reason to stop: write everything, reason through what each test should do today, and say so. Never
create temp or probe folders. Use pytest's `tmp_path`; every test must finish on its own.

## Allowed paths

`tests/codex/` only, plus `reports/red-team.md`. Everything else is read-only.

## Read first

`REVIEWS.md` (everything found so far: do not repeat it), R11 §2 invariants, `agent/sentinel/gate_v2/`,
`agent/sentinel/quarantine.py`, `watcher.py`, `nativehost.py`, `tests/conftest.py` (how EICAR is
assembled in memory; never write it to disk).

## Hunt for

Each case: harmless synthetic bytes, one test, a comment naming the invariant it probes.

* **Paths on NTFS:** trailing dots and spaces, `CON`/`NUL`/`COM1` names, names over 255 UTF-16 units,
  total path over 260 and over 32,767, `\\?\` and `\\.\` forms, 8.3 aliases, alternate data streams
  (`a.txt:evil`, a payload only in a stream, `::$DATA`), case-sensitive directories, lone surrogates,
  right-to-left override, combining and zero-width characters, hard links, symlinks, junctions and
  mount-point loops, a directory replaced by a junction mid-walk.
* **File state:** zero bytes, exactly at every limit and one past it, sparse files with huge logical
  size, reparse tags, file deleted while open, renamed during each stage, locked exclusively,
  growing during the scan, truncated during the scan, ChangeTime set back, read-only and hidden
  attributes, offline or cloud placeholder attributes, encrypted (EFS) when available.
* **Archives:** every parser differential you can build in memory: overlapping members, a member
  starting inside another, two end-of-central-directory records, prepended data, ZIP64 with lying
  sizes, name in Unicode extra field differing from the header, duplicate names, backslash and `..`
  names, empty names, nested limits, a ZIP that is also a valid PE or PDF, stored members containing
  a ZIP at an offset, Deflate bombs inside declared budgets, a data descriptor that lies.
* **Decisions:** the Cartesian product of statuses, coverage modes and evidence strengths across two
  stages, required and optional; assert the invariants hold for every combination, not examples.
  Cache: same identity under two policies, clock going backwards, expiry at the exact second.
* **Concurrency:** a stage that raises `BaseException` subclasses, cancellation at every stage boundary,
  the same file scanned by four workers, an event consumer stalled forever, reader closed twice.
* **Quarantine and restore:** quarantine during restore, disk full simulated, original folder gone,
  target replaced by a junction before restore, two items with one original path, a blob edited on disk.
* **Native host:** split frames, length prefix at every limit, deep JSON nesting, invalid UTF-8, huge
  numbers, surrogate escapes in paths.

Do not write a test that needs elevation, the network, a real antivirus or a real clamd. Mark a
case that depends on Windows features with a skip that names the reason.

## Your answer

English, concise: files and test counts, then a table of the cases you expect to fail today and why,
each with the code location. Say which cases you could not express as a test.
