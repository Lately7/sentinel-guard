# Sentinel Guard — project context for a new Claude or Codex session

Written 2026-11-02 at the end of a Claude Code session. Read this file fully
before touching the repository. Everything here was observed or run in that
session unless marked otherwise. Where this file and the code disagree, the
code wins: re-check before acting.

## 1. What the project is

Sentinel Guard is the owner's own Windows 11 anti-malware prototype:

* `agent/sentinel/` — Python agent (CLI, tray + Tk dashboard, real-time
  watcher, quarantine, threat feeds, native-messaging host for the browser).
* `extension/` — Chromium MV3 extension (Helium/Chrome/Edge) that blocks
  malicious domains and sends finished downloads to the agent.
* `tests/` (pytest), `extension/test/` (`node --test`).
* Rules for humans and agents: `AGENTS.md` (note: it still says Codex never
  edits files — that changes in commit C3d, see §7).

Location: `C:\Users\lately07\Desktop\Folder Group\sentinel-guard`
User-facing text is Vietnamese; code, identifiers and comments are English.

## 2. Environment on the owner's machine

| Item | State |
|---|---|
| OS | Windows 11 Home 10.0.26200 |
| Python | `.venv` = Python 3.15.1; `yara-x` installed; `pyflakes` added to the venv for linting (not in `pyproject.toml`) |
| Node | v24.20.0 |
| ClamAV | 1.5.4 installed at `C:\Program Files\ClamAV` (no config there) |
| ClamAV data | private config + DB under `%LOCALAPPDATA%\SentinelGuard\clamav\` (`clamd.conf`, `freshclam.conf`, `db\`: main 63, daily 28172, bytecode 339 — ~3.6 M signatures). clamd is currently **stopped** (`sentinel clamav start` starts it, ~20 s DB load) |
| YARA Forge core | **not installed** in the real data dir (`%LOCALAPPDATA%\SentinelGuard\rules` is empty). It was downloaded once into a temp home for testing: 5,134 rules, all compile under YARA-X. Install with `sentinel rules update` |
| Microsoft Defender | passive (Malwarebytes is the active AV), so the Defender layer is normally "unavailable" |
| Codex CLI | `codex-cli 0.164.0`; supports `codex exec -s read-only|workspace-write -C <dir> -` (prompt on stdin), `codex exec resume <id>`, `-o <file>` |

## 3. Git state

* Branch `main`, HEAD `01bc342` ("fix: Codex review round 2 …").
* Uncommitted changes, two different origins:
  * **Pre-existing before this session** (not gate work): `extension/icons/*.png`,
    `TASKS.md` (review table), the icon drawing in `agent/sentinel/tray.py`
    (`_icon_image`, colour constants), untracked `agent/sentinel/sentinel.ico`.
  * **Multi-layer scan gate, written by Claude in this session**: modified
    `README.md`, `agent/sentinel/__main__.py`, `config.py`,
    `engine/scanner.py`, `engine/signatures.py`, `engine/verdict.py`,
    `nativehost.py`, `tray.py`; new `engine/clamav.py`, `gate_ui.py`,
    `scanjob.py`, `yarafeed.py`, `tests/test_gate.py`; and this
    `docs/handoff/` folder.
* Nothing is committed yet. The owner reviews every diff before a commit.
* Line endings: the repo uses LF. Editing files with Python
  `Path.write_text()` on Windows silently converts them to CRLF — use the
  editor tools or write bytes.

## 4. What the scan gate does now

Every file goes through these layers in order; `Verdict.engines` records what
each layer said (`clean`, `detected`, `partial: …`, `skipped: …`,
`unavailable: …`, `error: …`):

| # | Layer | Code | Notes |
|---|---|---|---|
| 1 | Sentinel core | `engine/scanner.py`, `filetype.py`, `signatures.py` | SHA-256 + known-bad hash DB, built-in EICAR hash, deceptive names (double extension, RTLO, padding), PE structure, ZIP members (bounded), padded-PE heuristic (`pe.inflated`) for files > 100 MB with filler tail |
| 2 | Rule packs + YARA-X | `signatures.py`, `yarafeed.py` | JSON rule packs and `*.yar` in the rules dirs; YARA Forge severity from meta `score` (≥80 HIGH, ≥60 MEDIUM, else LOW); files > 64 MB: first 64 MB + last 8 MB |
| 3 | ClamAV | `engine/clamav.py` | private clamd on 127.0.0.1:33310 (`SENTINEL_CLAMD_PORT`), INSTREAM of the exact bytes that were hashed; files > 400 MB: first 400 MB streamed, status `partial`; `Heuristics.*`/`PUA.*` → MEDIUM, every other name → CRITICAL (to be replaced, see §7) |
| 4 | Microsoft Defender | `engine/defender.py` | `MpCmdRun -Scan -ScanType 3 -File … -DisableRemediation`, only when Defender is the active AV and the file type is risky |

Other parts:

* Scan cache: reused only when path/size/mtime/inode match **and** the
  SHA-256 of the bytes just read matches **and** `gate_id()` matches.
* `scanjob.py`: on-demand scan job (file, folder, quick, whole machine) with
  progress, cancel, junction skipping, agent-data-dir skipping.
* `gate_ui.py`: dashboard tab "Cổng quét" — layer status lights, ClamAV
  update/start buttons, scan buttons, results table with one column per
  layer, detail dialog. `tray.py` starts clamd at launch, downloads the ClamAV
  DB on first run, refreshes ClamAV (≥4 h) and YARA Forge (≥24 h) with the
  feeds.
* CLI: `sentinel scan … [-v] [--no-clamav]`, `sentinel clamav update|start|stop|status`,
  `sentinel rules update`.
* Verified visually: dashboard screenshot with all four layers and a gate
  scan of harmless samples.

## 5. Test status (real results from the session)

* Last completed `pytest` run on the current code: **82 passed** (78 test
  functions, some parametrized). After that only `README.md` changed.
* `tests/test_gate.py` (31 tests) uses a fake clamd on localhost; three
  `test_real_clamav_*` tests talk to a real clamd and **skip** when none is
  running. They passed while clamd was running: EICAR (assembled in memory)
  detected in raw, zip, zip-in-zip, tar.gz, gzip, bzip2, xz and a MIME
  attachment; clean containers stay clean.
* `node --test extension/test/` was **not run** in this session.
* A false-positive measurement over System32 / Program Files was started and
  cancelled before producing a result. No FP number exists yet.

## 6. Fixes made in the session (beyond the gate itself)

* Cache poisoning: same-size content swap with the old mtime restored was
  served from cache as clean → cache now requires the same SHA-256
  (regression test `test_cache_is_not_fooled_by_same_size_swap_with_restored_mtime`).
* Files padded past every size limit → ClamAV still scans the first 400 MB,
  rules/YARA see front + tail, `pe.inflated` flags filler-padded executables.
* clamd silently answers OK for files above `MaxFileSize`; limits are now set
  so the agent knows when ClamAV did not see the whole file.
* Native host: an oversized message length prefix was drained with one
  `read(n)` (up to 4 GB allocation) → chunked drain.
* Dashboard bug (pre-existing): notebook pages were also `pack()`ed, which
  stacked tables over the tab bar.
* Checked and **not** a bypass: moving a whole folder into a watched folder
  (watchdog reports the files inside).

## 7. Decisions locked with the owner

1. Keep the Python core. No Rust rewrite. Loki-RS dropped. capa optional,
   explanation only, later. PySide6 optional.
2. Order: baseline commit → Codex characterization tests → Scanner Contract v1
   → Codex regression review → quarantine hardening. One reviewable change
   group per commit.
3. Characterization tests must not legitimize bugs: known-dangerous behaviour
   gets a test of the **desired** behaviour marked
   `xfail(strict=True)` with an RT id.
4. Engine failure is never reported as clean. Contract v1 separates `status`
   (completed/partial/skipped/unavailable/error/timeout) from `verdict`
   (clean/suspicious/malicious/unknown) and adds `coverage` (byte ranges),
   `sha256`, `size`, `engine_version`, `db_version`, `duration_ms`, `error`,
   `contract_version`, structured `signature_id`.
5. One conclusive signature from one engine is enough for "malicious"; no
   voting. "Conclusive" = known-bad hash, ClamAV minus a weak-name denylist,
   user rule packs with severity critical, Defender threat. A single YARA
   Forge match stays **suspicious**.
6. Detection policy and auto-quarantine policy are separate.
   `should_auto_quarantine(verdict, policy) -> Decision` with reason codes;
   default mode `legacy-v0` keeps today's behaviour until `evidence-v1` is
   switched on. Unknown ClamAV names quarantine by default; weak names
   (denylist) only notify. Partial coverage never yields "trusted clean" but
   does not block quarantine when a conclusive signature matched in the
   scanned range. EICAR is quarantined like real malware (it is how users
   verify protection), labelled as a test file.
7. Restore ≠ trust: restore creates a path+hash exception only; "Trust" is a
   separate explicit action. Watcher, CLI and on-demand scans exclude
   Sentinel's own data (quarantine, ClamAV DB, cache, logs), not all of
   `%LOCALAPPDATA%`.
8. False-positive measurement: Claude scans legitimate software already on
   the machine read-only, with a disposable `SENTINEL_HOME`, auto-quarantine
   off; plus Codex's synthetic manifest corpus for regression. Measure at the
   baseline and again after the refactor.
9. Codex's role: independent security reviewer and test engineer, harmless
   synthetic inputs only. In test rounds it may write only `tests/codex/**`
   and `reports/red-team.md`; a scope checker enforces it.

## 8. Commit plan (agreed with Codex in round 2)

| Commit | Content |
|---|---|
| C1 | Pre-existing icon/TASKS.md/tray-icon/`sentinel.ico` changes only |
| C2a | Gate code + its tests exactly as they are now; branch labelled non-release (known auto-quarantine defects) |
| C2b | `docs/baseline.md` only: C2a hash, ClamAV engine/DB versions, commands, pass/skip counts with and without clamd, pytest + node |
| C3a | Typed `DefenderResult` (clean/malicious/error/timeout/unavailable) with runner injection; `is_active()` made refreshable (today `@lru_cache` forever) |
| C3b | Content-digest gate identity, cacheability rules, ClamAV reload invalidation |
| C3c | Keep `skipped`/coverage on oversized ZIP; coverage text from config, not hard-coded |
| C3d | Revise the two tests that lock rejected decisions (`tests/test_agent.py:31` global trust after restore, `tests/test_gate.py:109` every ClamAV name conclusive); update `AGENTS.md` for Codex's role; `tools/check_codex_scope.ps1`; RT registry; decisions in `REVIEWS.md` |
| C3e | Native host exact-read loop for message bodies |
| C3f | Test seam only: keyword-only `client: ClamdClient \| None = None` on `ClamAVEngine` (Protocol: `ping`, `version`, `instream`, `instream_file`); default = today's TCP client; one real socket integration test stays. No watcher clock (monkeypatch `watcher.time.monotonic`), no public gate-identity API |
| C4 | `CODEX_TASK_1a.md` and `CODEX_TASK_1b.md`, both pinned to the C3f hash and the scope-script digest |

Then: Codex round 1a (gate, cache, Defender, ClamAV names, native host, CLI,
quarantine) and 1b (watcher, races, hostile-input corpus) — no production
commit between them, both must pass before Contract v1 → Contract v1 (`engine/contract.py`,
legacy adapter, additive `scan_result` in the native response) → Codex
regression review → `clamav_policy.py`, `quarantine_policy.py`, Restore vs
Trust, data-dir exclusion → one-button smart scan with the live pipeline view
(needs Contract v1's `ScanEvent`; §10) → second FP/FN measurement.

## 9. Known issues registry (proposed ids)

| Id | Issue |
|---|---|
| RT-001 | No evidence-based auto-quarantine policy; ClamAV weak names (e.g. `Win.Trojan.Suspect-34`, seen on a harmless ZIP whose member is named `invoice.pdf.exe`) are CRITICAL |
| RT-002 | Restore grants global hash trust |
| RT-003 | Watcher does not exclude Sentinel's data dir |
| RT-004 | Partial scans can appear clean |
| RT-005 | Cross-layer TOCTOU (files > 64 MB are reopened; Defender scans the path later) |
| RT-006 | Native host reads the message body with a single `read(n)` |
| RT-007 | CLI walk does not exclude Sentinel data; `scanjob` exclusion not canonicalized with `realpath` |

Also found by Codex, fixed in C3a–C3c: Defender error/timeout reported as clean;
gate id uses rule counts only and caches incomplete results; `skipped`
cleared for oversized ZIP. Minor: contradictory layer status when
`pe.inflated` fires; `scan_bytes()` has no Defender status.

## 10. Owner's product requirement: one Scan button, live pipeline

One **Scan** button. While it runs the user watches the pipeline live: prepare
(SHA-256, type) → Sentinel core → rules + YARA-X → ClamAV → Defender → risk
correlation → action, each stage lighting up per file, with counters, the
current file and a live event log. A clickable mock-up was shown in the
session. Design converged in round 3 (`codex-review-r3.md`, U1–U4):

* **Default scope = smart scan**; whole machine is a secondary, confirmed
  action. Smart scan = watched folders; user + All Users Startup; HKCU/HKLM
  `Run`/`RunOnce` in 32- and 64-bit views; readable Task Scheduler executable
  actions via the Task Scheduler API (not raw `System32\Tasks`); images of
  running processes via `QueryFullProcessImageNameW` with
  `PROCESS_QUERY_LIMITED_INFORMATION`. No process memory, no elevation, no
  UNC, no whole `%LOCALAPPDATA%`; dedupe by canonical path + file identity;
  exclude Sentinel data before queueing; count inaccessible entries.
* **Progress events**: separately versioned `ScanEvent` (event_version,
  scan_id, opaque scan-local file_id, sequence, stage, state
  started/finished/skipped/error/cancelled, duration_ms, result_code). No full
  paths, hashes, command lines, usernames or raw engine output in the portable
  schema (`--include-paths` opt-in for CLI JSONL). Scanner never calls Tk:
  bounded non-blocking queue, worker-side counters, capped ring, UI snapshots at
  ~10 Hz, terminal detection/error/action events never dropped. Stress test:
  500k events with a paused consumer stays bounded and non-blocking.
* **Concurrency**: files in parallel, stages of one file sequential on the
  same bytes. Start with 2 file workers (max 4), ClamAV 2–3 concurrent,
  Defender pool 1, weighted in-flight byte budget ~192–256 MB (current
  `_read` joins chunks, so 64 MB logical ≠ 64 MB resident). Every enabled stage
  emits an event; a stage skipped after a conclusive hit emits `skipped` with
  a reason. Revalidate file identity before and after Defender.
* **Cancellation**: cooperative between chunks/members; close only the active
  INSTREAM socket; Defender via `Popen` in a Job Object, terminate the job.
  A cancelled file is `status=cancelled`, `trusted_clean=false`, verdict
  unknown (or suspicious/malicious if already established), never cached. A
  file with an accepted conclusive detection finishes its action decision even
  when the wider scan is cancelled; an in-progress quarantine completes or
  rolls back.

## 11. Outcome of round 3 (Claude's rebuttals)

* R1 test seams: only the ClamAV client seam in C3f; Defender runner goes
  into C3a. Seams keyword-only, default = today's behaviour.
* R2 cacheability: availability classes — `disabled_by_policy` cacheable;
  `not_installed` / `not_active` cacheable only if re-evaluated before reuse;
  `not_running`, `starting`, `connection_error`, `timeout` never cached;
  `partial_by_policy` (fixed ranges) cacheable but stays not-trusted-clean;
  `partial_runtime` never cached.
* R3 clamd anti-spoofing: listener PID → handle with
  `PROCESS_QUERY_LIMITED_INFORMATION` → creation time + canonical image path +
  file identity recorded at launch; re-query after opening; better, match the
  exact connected socket tuple in the owner-PID table while INSTREAM is open.
  Unverified daemon: its OK does not count as clean coverage, its detections
  are notify-only evidence, never auto-quarantine. Long term: one
  Sentinel-owned clamd supervisor with an ACL-protected broker.
* R4 split round 1 into 1a/1b pinned to the same commit: agreed.
* R5 CLI exit precedence: malicious 2 > unreadable/changed/timeout/engine
  failure 3 > suspicious 1 > clean 0. Deterministic partial coverage is not
  exit 3.
* R6 strong families: `Exploit.*`, `CVE_*`, Virus, Worm, Ransomware, Backdoor,
  Rootkit, Bootkit, Trojan, Dropper, Downloader, Botnet, Infostealer, Spyware,
  Keylogger, EICAR/test signatures. Weak rules take precedence
  (`PUA.Win.Exploit.*` stays weak). `Generic`/`Gen`/`Agent` are not weak; no
  `Packed`/`Obfuscated` rule until the FP measurement shows a need.

Nothing is left open from rounds 1–3 except the R3 implementation choice
(listener check vs. socket-tuple check vs. broker), to be decided when
quarantine hardening starts.

## 12. Safety rules for every session

* Never create, download, execute or spread real malware. Positive samples are
  the EICAR string assembled **in memory** (never written to disk — Defender
  and other AVs react to it, and it is a repo rule) or the harmless test
  marker matched by a test-only rule.
* Do not build evasion, persistence, credential theft, or anything that
  disables security software. Do not touch Defender settings, exclusions or
  registry security settings. Red-team work means finding logic defects in
  this project's own code with synthetic inputs.
* Tests use a temporary `SENTINEL_HOME`; never the real
  `%LOCALAPPDATA%\SentinelGuard` database, quarantine or settings.
* No shell strings: argv arrays, `shell=False`.
* Admin rights, files outside the project, large downloads, commits and pushes
  need the owner's approval first.
* Never record a result that was not produced by running the command.

## 13. Practical lessons from this session

* A previous red-team session was stopped by the model's safety filter
  because its brief asked for "evasion/bypass techniques". Frame Codex work
  as review, characterization, fuzzing and regression testing of this
  project's own code with harmless synthetic data.
* PowerShell 5.1 pipes text to native programs with `$OutputEncoding` =
  ASCII: set `$OutputEncoding = [System.Text.UTF8Encoding]::new($false)`
  before `Get-Content -Raw -Encoding UTF8 file | codex exec … -`, or keep
  Codex briefs in English.
* Codex `workspace-write` blocks network, possibly localhost too: socket-based
  tests (fake clamd) may skip inside Codex; Claude reruns them outside and
  records the result. A sandbox skip is not a pass.
* `workspace-write` does not restrict which files Codex writes; the scope
  checker and a `git status` review do.
* ClamAV names can be container-metadata signatures (filename inside an
  archive), and INSTREAM replies carry only the name — no offset or member.

## 14. Commands

```powershell
.\.venv\Scripts\python -m pytest -q
node --test extension/test/
.\.venv\Scripts\python -m sentinel clamav start      # needed for test_real_clamav_*
.\.venv\Scripts\python -m sentinel clamav status
.\.venv\Scripts\python -m sentinel clamav stop
.\.venv\Scripts\python -m sentinel scan <path> -v --no-cache
.\.venv\Scripts\python -m pyflakes agent/sentinel tests
```
