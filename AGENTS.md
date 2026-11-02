# AGENTS.md — rules for humans and coding agents

Sentinel Guard is a Windows desktop agent (real-time file/malware protection)
plus a Chromium MV3 extension (real-time web protection), built first for the
Helium browser and also working in Chrome and Edge.

## Roles

| Who    | Does                                                                 |
|--------|----------------------------------------------------------------------|
| Claude | All production code and integration, tests, running the tests, reports and docs, review of every Codex change |
| Codex  | Optional, while its quota lasts (owner decision 2026-11-02): long independent background work; writes only what a round's brief allows (below). No step may wait for it |

Codex rounds and what each may write:

| Round | Sandbox | May write |
|---|---|---|
| Review / research | `codex exec -s read-only` | nothing (answer only; Claude records it) |
| Test round | `-s workspace-write`, own worktree | `tests/codex/**`, `reports/red-team.md` |
| Asset round | `-s workspace-write`, own worktree | `assets/brand/**` |
| Gate v2 (owner decision 2026-11-02) | `-s workspace-write`, own worktree and branch | the paths its task file names |

`workspace-write` does not restrict paths by itself. After every writing round
Claude runs `tools/check_codex_scope.ps1 -Base <start commit> -Allow <paths>`
and reviews the diff before anything is merged. Claude checks every finding
and applies it or rejects it with a reason in `REVIEWS.md`.

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
node --test "extension/test/*.test.mjs"     # extension unit tests (Node 24 needs the glob)
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
