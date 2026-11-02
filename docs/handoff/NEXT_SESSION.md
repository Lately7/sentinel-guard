# Handoff for the next Claude session (written 2026-11-02 ~17:45)

You have no memory of earlier sessions. Everything you need is in this repo.
Code beats documents: when they disagree, trust the code and say so.

## 1. Where things are

* Repo: `C:\Users\lately07\Desktop\Folder Group\sentinel-guard`, branch
  **`gate-baseline`** (local only, never pushed). `main` is the old base.
* Read in this order: `docs/ROADMAP.md` (one-page plan, RT registry
  summary), this file, `AGENTS.md`, `REVIEWS.md` (RT-001…RT-052 with
  status), `docs/handoff/PROJECT_CONTEXT.md` (§7 and §11 are locked owner
  decisions), `docs/research/R11-gate-v2-knowledge-pack.md` (Gate v2 spec).
* Research by Codex (all read-only, verified where noted):
  `docs/research/R8a…R12d` (ClamAV/YARA-X/capa/osquery/Wazuh source studies,
  commercial AV, malware), `docs/handoff/codex-*.md` (review rounds r4–r7,
  GUI review r13).
* Source checkouts used for research (read-only, outside the repo):
  `C:\Users\lately07\Desktop\Folder Group\research\` — clamav-1.5.4,
  yara-x-1.22.1, capa-10.0.0, capa-rules, osquery-5.24.0, wazuh-4.14.9.
  Test-data folders were deliberately not checked out (no malware samples).

## 2. State at handoff

* Tests (last real run): `.\.venv\Scripts\python -m pytest -q` →
  **119 passed, 4 skipped, 2 xfailed** (4 skips = real-clamd tests while
  clamd is stopped; 2 xfails = known issues RT-001, RT-002 in
  `tests/test_known_issues.py`). `node --test "extension/test/*.test.mjs"` →
  **32 passed**. (`node --test extension/test/` does not work on Node 24.)
* Desktop UI v4 (Tk, dark, icon sidebar): `agent/sentinel/theme.py`,
  `overview_ui.py`, `gate_ui.py`, `tray.py`, `engine_status.py`.
  Screenshots `docs/ui/v4/`. Slow probes (Defender PowerShell 16 s, clamd
  pings) must never run on the Tk thread — use `EngineStatus.snapshot`.
* Extension restyled (`docs/ui/extension/`). A syntax error in
  `background.js` broke the whole extension from commit 0a29a6e until
  d422f74; `extension/test/syntax.test.mjs` now guards against that.
* Gate v2: research and spec are done (R11). **No Gate v2 code exists yet.**

## 3. Open problem: RT-022 "Mở một lần" (one-time pass) does not open the page

What exists (d422f74): warning page (`extension/src/blocked.html/js`) has
"Mở một lần" → message `{type:"proceed", url, always:false}` →
`background.js` `allowOnce(tabId, host)` adds a **session** DNR rule
`{id: 950000+n, priority 10, action allow, condition {requestDomains:[host], tabIds:[tabId]}}`
(`rules.js buildOnceRule`), stores it in `chrome.storage.session.once`,
then calls `chrome.tabs.update(tabId, {url})`. It is dropped when the tab
navigates to another host or closes. "Luôn tin cậy" (`always:true`) uses
the old persistent `trust(host)` (dynamic allow rules, priority 10).

Observed in Helium 156 (`tools/helium_e2e.mjs`): the session rule exists
(correct tab id, host, priority) but the tab is redirected to
`blocked.html?k=x` again (the **dynamic** redirect rule id 1, priority 1).
`getMatchedRules` showed the redirect matching once with `tabId -1` (when
the page itself navigated with `location.replace`) — hence the switch to
`tabs.update` — but it still redirects with `tabs.update`, and also when
`tabIds` is removed. Not yet checked: whether **"Luôn tin cậy" actually
opens a DNR-blocked host** (the e2e only checks the stored allowlist).

Ideas, in order: (1) add an e2e check that "always trust" really opens
`blocked-selftest.sentinelguard.invalid` (DNS will fail → `chrome-error://`
is success, `blocked.html` is failure); (2) if always-trust works, put the
one-time rule in the **dynamic** ruleset (id range 950000+, removed on leave
/close/browser start) instead of session rules; (3) read Chromium's DNR docs
on precedence between session and dynamic rules (allow vs redirect,
priority across rulesets) — cite the source in the commit; (4) keep the
`tabIds` restriction only if it works. It fails safe today.

Run the e2e without touching the real agent data (verified that Helium
passes `SENTINEL_HOME` to the native host):

```powershell
$env:SENTINEL_HOME = Join-Path $env:TEMP ("sg-e2e-" + [guid]::NewGuid().ToString("N").Substring(0,8))
New-Item -ItemType Directory $env:SENTINEL_HOME | Out-Null
.\.venv\Scripts\python -m sentinel block blocked-selftest.sentinelguard.invalid
node tools/helium_e2e.mjs extension <optional-screenshot-dir>
```

Success = `once_opened: true`, `once_not_trusted: true`,
`once_dropped_after_leaving: true`, `always_trusted: true`, `sw_errors: []`.

## 4. How to drive Codex

* Tool: `tools/codex_run.ps1` (model **gpt-6-sol**, effort **high**, pinned;
  owner's choice). Example:
  `powershell -NoProfile -ExecutionPolicy Bypass -File tools\codex_run.ps1 -Brief <brief.md> -Out <answer.md> -Sandbox read-only`
  Run it in the background; the log is `<answer>.log`.
* Read-only rounds may run in this repo. **Writing rounds run only in a
  separate git worktree on their own branch**, with `-Sandbox workspace-write
  -WorkDir <worktree>`. After every writing round: `git -C <worktree> status`,
  `powershell -NoProfile -File tools\check_codex_scope.ps1 -Base <start> -Allow "<paths>"`
  (run from the worktree), read every changed line, run the tests, then
  merge with `--no-ff` into `gate-baseline` and record the outcome in
  `REVIEWS.md`. Briefs to Codex are in English.
* Git Bash rewrites `/src/`-style arguments into Windows paths; use
  `MSYS_NO_PATHCONV=1` or PowerShell for git sparse/worktree paths.

## 5. Tonight's tasks, in order

1. **RT-022** (section 3). Commit with the real e2e result.
2. **Gate v2 milestone 1 (Codex writes, you review):** R11 §8 row 1 —
   `agent/sentinel/gate_v2/contract.py`, `coverage.py`, `policy.py` (pure:
   types, coverage ledger, verdict/action policy with reason codes, no I/O)
   plus tests in `tests/gate_v2/`. Write the task file
   `docs/handoff/CODEX_TASK_GATE_V2_M1.md` (pin the start commit, list the
   allowed paths, the R11 sections to implement, the invariants from R11 §2
   that must have tests, and "no change outside the allowed paths"). Create
   the worktree: `git worktree add ..\sentinel-guard-gate-v2 -b codex/gate-v2-m1 HEAD`.
   Allowed paths: `agent/sentinel/gate_v2/`, `tests/gate_v2/`. Nothing in
   the existing scanner changes in M1. Merge only if the full test suite
   passes.
3. If M1 merged cleanly and time remains: **milestone 2** (identity +
   orchestrator skeleton + events) the same way, allowed paths
   `agent/sentinel/gate_v2/`, `tests/gate_v2/`; the adapter shell in
   `engine/scanner.py` waits for milestone 6.
4. Independent fixes (yours, small commits, tests first):
   RT-016/017/018 watcher (use `docs/research/R12d-wazuh.md` §2 "Concrete
   RT-016–RT-018 changes"), RT-021 allowlist paging/overflow.
5. Before stopping: update `docs/ROADMAP.md` (statuses, test counts) and
   write `docs/handoff/NIGHT_REPORT.md` in Vietnamese for the owner:
   what was done (commits), real test results, what failed, what needs
   the owner.

## 6. Rules (owner-approved; do not relax)

* Commit freely on `gate-baseline` (owner said "auto commit"); **never
  push**, never force, never rewrite pushed history.
* No admin rights, no system/security setting changes, no Defender
  changes, no new downloads, no files outside the repo except the
  `..\sentinel-guard-*` worktrees and `%TEMP%`.
* Never create, download or run malware. Positive samples: EICAR built in
  memory (never on disk) or the harmless marker rule from `tests/conftest.py`.
  No evasion techniques.
* Tests and previews use a temporary `SENTINEL_HOME`; never the real
  `%LOCALAPPDATA%\SentinelGuard` data.
* Report only results you actually ran; say which tests were skipped and
  why. If a step fails, say so in the report; do not paper over it.
* Owner decisions open in R11 §9 stay open: use the proposed defaults,
  keep `legacy-v0` auto-quarantine, and list the questions in the report.
* User-facing text Vietnamese; code, identifiers, comments English;
  comments explain why. Repo uses LF (write bytes, not `Path.write_text`).
