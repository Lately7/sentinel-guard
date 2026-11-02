# AGENTS.md — rules for humans and coding agents

Sentinel Guard is a Windows desktop agent (real-time file/malware protection)
plus a Chromium MV3 extension (real-time web protection), built first for the
Helium browser and also working in Chrome and Edge.

## Roles

| Who    | Does                                                                 |
|--------|----------------------------------------------------------------------|
| Claude | All logic and code, all tests, running the tests, reports and docs   |
| Codex  | Read-only review of Claude's logic; findings go into `REVIEWS.md` via Claude |

Codex never edits files in this repository. Each review is started with
`codex exec -s read-only`, its findings are checked by Claude, and Claude
applies (or rejects, with a reason) every finding.

## Layout

| Path               | Contents                                                |
|--------------------|---------------------------------------------------------|
| `agent/sentinel/`  | Python agent: engine, DB, feeds, watcher, native host, tray UI |
| `extension/`       | MV3 extension: service worker, warning page, popup, rules |
| `tests/`           | pytest suite                                            |
| `extension/test/`  | `node --test` suite                                     |
| `reports/`         | generated test/scan reports                             |

## Conventions

* Python 3.12+, type-annotated. `agent/sentinel/engine/`, `db.py`,
  `nativehost.py`, `feeds.py` are stdlib-only so the native host starts fast;
  `watchdog`, `pystray`, `Pillow` are imported only by `watcher.py`/`tray.py`.
* Never execute, import, or `eval` a scanned file. Read bytes only, with size
  limits. Never write a live malware sample (or EICAR) to disk in tests:
  scan bytes in memory, or use a harmless marker added as a test-only rule.
* Detection functions never raise on hostile input: malformed data becomes a
  finding or an empty result.
* Heuristics alone must not reach the `malicious` label for common legitimate
  software; only signatures, blocklists, Defender, or several strong signals
  together may. Automatic quarantine happens only on `malicious`.
* Extension: plain ES modules, no bundler, no remote code, every message from a
  content script or page is validated in `background.js` before use.
* No shell strings: spawn with argv arrays and `shell=False`.
* User-facing text is Vietnamese; code, identifiers and comments are English.
* Comments explain *why*, not what.

## Commands

```powershell
python -m venv .venv; .\.venv\Scripts\python -m pip install -e ".[ui,dev]"
.\.venv\Scripts\python -m pytest              # Python tests
node --test extension/test/                  # extension unit tests
.\.venv\Scripts\python -m sentinel install   # register native host + autostart
.\.venv\Scripts\python -m sentinel tray      # run the agent with tray icon
.\.venv\Scripts\python -m sentinel report    # write reports/status report
```

## Review process

1. Acceptance criteria are in `TASKS.md`.
2. Codex reviews each finished module read-only; Claude records the outcome
   of every finding in `REVIEWS.md`.
3. Tests must pass before a milestone is marked complete. Never record a
   result that was not produced by running the command.
