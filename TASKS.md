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
| A3 | protected install, consent helper, acceptance driver | merged after review, REVIEWS.md §A3 |
| R15, R16 | code review, service install and ACL research | saved in docs/research |
| Scope A5 | scope, USN, process samples, rescans (`9db4210`) | stopped by quota; rewritten and merged `088041a` |
| Reputation ETW | feeds, ETW, canaries, burst, simulator (`a138093`) | stopped by quota; corrected and merged `ca966a6`, ETW dormant |
| R1 (read-only) | window stations and the worker in Session 0 | no cause established; advised recording the failure |
| R2 (read-only) | journal observer blind spots | fed SVC3B and SVC9 |
| R3 (read-only) | cross-review of the SVC3 diff | fed SVC3B |
| R4 (read-only) | automatic actions as LocalSystem | fed SVC6 and SVC8 |
| R5 (read-only) | cross-review of the merged SVC1, SVC2, SVC4 | two fixes in `9fc8169`, the rest fed SVC7 |
| SVC1 | dead worker, native host fallback, tray status | merged `ec06f6c`; reviewed in REVIEWS.md |
| SVC2 | offline feeds and worker rule limit | merged `590f7e1`; reviewed in REVIEWS.md |
| SVC3 | journal observation and quiet window | merged in `d2305b0`; reviewed in REVIEWS.md |
| SVC3B | observer and journal follow-up | merged with SVC3 in `d2305b0`; reviewed in REVIEWS.md |
| SVC4 | service log and installed-shape tests | merged `6797f6c`; reviewed in REVIEWS.md |
| SVC5 | worker failure diagnostics and termination | merged `ea43575`; reviewed in REVIEWS.md |
| SVC6 | bounded stop, catch-up and repair reporting | merged `94b5ad9`; reviewed in REVIEWS.md |
| SVC7 | worker probe, rescan key, event pruning | merged `695935a`; reviewed in REVIEWS.md |
| SVC8 | cloud placeholders and the download mark | merged `8721368`; changed in review |
| SVC9 | journal lookup cost, sleep and lag reporting | merged `edb0f00`; reviewed in REVIEWS.md |
| SVC10 | false-positive sampler with every engine | merged `b7daecb`; tool only, no rate measured |
| DOCS1 | records of these rounds | corrected in review, merged with this entry |

Outcomes are recorded in `REVIEWS.md`.
