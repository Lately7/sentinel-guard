# TASKS.md

> Tiến độ hiện tại và kế hoạch: **`docs/ROADMAP.md`**. Mục dưới đây là tiêu chí gốc của Milestone 1.

## Milestone 1 — working agent + extension

Acceptance:

* `python -m sentinel scan <path>` prints a verdict per file; exit code 2 if
  anything is malicious, 1 if suspicious, 0 otherwise.
* Real-time watcher scans new/changed files in the watched folders and
  quarantines `malicious` ones; quarantine can be listed and restored.
* Feeds (MalwareBazaar hashes, URLhaus, OpenPhish, crypto-miner hosts) update
  into the local SQLite DB; failures of one feed don't stop the others.
* Optional second opinion from Microsoft Defender (`MpCmdRun.exe`).
* Extension (Helium/Chrome/Edge) blocks blocklisted domains for every request
  type, warns on risky top-level URLs, sends finished downloads to the agent.
* `python -m sentinel report` writes an HTML + JSON status report.
* `pytest` and `node --test extension/test/` pass.

## Module specs (Claude)

### URL heuristics — `extension/src/url_heuristics.js`

`scoreUrl(url) -> {score, reasons}` and `registrableDomain(host)`. Structural
signals only (IP host, punycode/mixed script, deep subdomains, userinfo,
odd ports, brand name outside its own domain, edit-distance-1 lookalikes of a
small brand list). Popular legitimate sites must stay below 70.

### File type checks — `agent/sentinel/engine/filetype.py`

`sniff(head) -> str` and `check_name(name, head) -> list[Finding]`: double
extension, bidi override characters in names, executable content behind a
document/image extension.

## Codex reviews

| # | Scope | Status |
|---|-------|--------|
| R1 | whole repository | done: 28 findings, 27 fixed, 1 partly |
| R2 | round-1 fixes + new code | done: 26 findings, 24 fixed, 2 partly |
| R3 | round-2 fixes (final) | see REVIEWS.md |

Outcomes are recorded in `REVIEWS.md`.
