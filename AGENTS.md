# AGENTS.md — rules for humans and coding agents

Sentinel Guard is a Windows desktop agent (real-time file/malware protection)
plus a Chromium MV3 extension (real-time web protection), built first for the
Helium browser and also working in Chrome and Edge.

## Layout

| Path                          | Owner (default) | Contents                                        |
|-------------------------------|-----------------|-------------------------------------------------|
| `agent/sentinel/`             | Claude          | Python agent: engine, watcher, native host, UI  |
| `agent/sentinel/engine/pe.py` | Codex           | PE (Windows executable) static heuristics       |
| `extension/`                  | Claude          | MV3 extension (service worker, pages, rules)    |
| `extension/src/url_heuristics.js` | Codex       | URL risk scoring (pure, no `chrome.*`)          |
| `extension/src/content/`      | Codex           | page_guard.js, clipboard_guard.js               |
| `tests/`                      | Claude + Codex  | pytest suite (Codex owns files it creates)      |
| `extension/test/`             | Claude + Codex  | `node --test` suite (Codex owns files it creates) |
| `*.md`                        | Claude          | documentation (Codex may review)                |

Two agents never edit the same file at the same time. A Codex task names the
files it may create or change; everything else is read-only for that task.

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
  software; only signatures, blocklists, or several strong signals together
  may. Automatic quarantine happens only on `malicious`.
* Extension: plain ES modules, no bundler, no remote code, every message from a
  content script or page is validated in `background.js` before use.
* No shell strings: spawn with argv arrays and `shell=False`.
* User-facing text is Vietnamese; code, identifiers and comments are English.
* Comments explain *why*, not what.

## Commands

```powershell
python -m venv .venv; .\.venv\Scripts\python -m pip install -e ".[ui,dev]"
.\.venv\Scripts\python -m pytest          # Python tests
node --test extension/test/              # extension unit tests
.\.venv\Scripts\python -m sentinel install   # register native host + autostart
.\.venv\Scripts\python -m sentinel tray      # run the agent with tray icon
```

## Review process

1. Interfaces and acceptance criteria for each Codex task are in `TASKS.md`.
2. Codex results are summarised in `TASKS.md` (Codex log).
3. Claude reviews every Codex diff before committing it.
4. Never record a result that was not produced by running the command.
