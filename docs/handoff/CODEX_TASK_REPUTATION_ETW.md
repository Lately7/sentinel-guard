# Codex task — reputation lookups and the measured canary prototype (≈7/10 work)

The owner approved the ≈7/10 target. Claude reviews every line, runs the tests and merges.
Stay on the branch this worktree is on; do not commit.

**Sandbox note:** you cannot run pytest in this sandbox (temp folder denied). That is *not*
a reason to stop: implement everything, re-read your code against each test, and say which
test covers what. Never create temp or probe folders. Claude runs the suites.

## Read first

`docs/research/R14-etw-ransomware-detection.md` (the design: follow it, including its decision
gate), `docs/ROADMAP.md` ("mục tiêu ≈7/10"), `agent/sentinel/feeds.py`, `agent/sentinel/urlintel.py`,
`agent/sentinel/indicators.py`, `agent/sentinel/service/worker.py`.

## Allowed paths

New files only: `agent/sentinel/reputation.py`, `agent/sentinel/service/etw.py`,
`agent/sentinel/service/canary.py`, `agent/sentinel/service/burst.py`, `tools/fileop_simulator.py`,
`tests/test_reputation.py`, `tests/test_service_etw.py`, `tests/test_service_canary.py`,
`tests/test_service_burst.py`, `tests/test_fileop_simulator.py`. Everything else is read-only.

## `reputation.py`

Feed adapters that plug into the shape `feeds.py` already uses, for MalwareBazaar recent hashes,
URLhaus and ThreatFox, through an injected HTTP transport with size caps. Only tested with canned
responses: **no test touches the network**, and nothing is downloaded in this round. Malformed rows
are skipped and counted. Optional VirusTotal hash lookup for new downloads: hash only, never the
file; off by default; needs a key in settings; bounded rate; a failed lookup is a typed gap. A
reputation hit from a feed is a known-bad hash for the core stage; a VirusTotal count is
`SUPPORTING`, never conclusive alone.

## ETW and canaries (observe and alert only)

Build R14 §8 milestones 1 to 3 as code: no suspension of any process in this round.

* `service/etw.py`: `ctypes` real-time consumer of a private, versioned session per R14 §2, with a
  bounded no-I/O callback and an aggregation thread. Payload parsing is pure and hostile-input
  safe, tested from canned event bytes. Loss counters; any loss opens a coverage gap. Never stop or
  attach to a session it does not own; orphan cleanup only for its own marker. A capability probe
  function reports what this machine allows. Starting a real session needs elevation: tests use
  fakes, and a real start that is denied gives a typed result.
* `service/canary.py`: placement plan, creation, protected record of file id, size and hash,
  revalidation. Files are ordinary harmless documents. Paths are injected and tests use `tmp_path`.
  Creating canaries in real user folders is **not** done by this code unless the caller passes the
  owner-approved roots.
* `service/burst.py`: pure scoring and the incident state machine of R14 §6, thresholds as named
  hypotheses, alert only, `GAP/ABSTAIN` on loss, all bounds from R14 §6 with counters.
* `tools/fileop_simulator.py`: the harmless harness of R14 §7. It refuses to run unless the target
  directory was created by the harness and holds its marker file; it refuses roots, profile
  directories, reparse points and network paths; it creates its own synthetic corpus; it transforms
  with a fixed test key, is fully reversible, and has no self-start, no spreading, no network and no
  deletion outside that directory. Tests prove each refusal.

## Rules

Python 3.12+, typed, stdlib only, comments explain why, LF. No malware, no samples, no downloads, no
security-setting changes, nothing that disables or evades any product.

## Your answer

English, concise: files and line counts, API, test per requirement, what Claude must wire, and what
only an owner-run measurement can prove.
