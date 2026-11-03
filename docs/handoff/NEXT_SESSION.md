# Handoff for the next Claude session (written 2026-11-02, ~19:50)

You have no memory of earlier sessions. Everything you need is in this repo.
Code beats documents: when they disagree, trust the code and say so.

**Update 2026-11-02, later that evening.** The owner approved the ≈7/10 target and
full autonomy, except what §7 forbids. `gate-baseline` is now `main`, pushed to
`origin`. M5 and M6 part 1 are merged; R15 is fixed except R15-2 (A3) and R15-8
(M7). Claude never elevates: this session runs unelevated.

**Update 2026-11-02 ~20:20 — read `docs/handoff/PLAN.md` next.** It replaces the
order of work in §3–§5 below. Owner decision: Claude owns all the work; Codex only
uses up its remaining quota on long background tasks, and no step may wait for it.
§4 still describes how to run a Codex round. Five rounds started at 20:13: M5 round 2,
M6 part 1, R14, R15, R16; results in `%TEMP%\sg-codex\`. The M5 draft is `b66cb3f` on
`codex/gate-v2-m5`; M6 part 1 has its own worktree `..\sentinel-guard-gate-v2-m6`.
§2's "393 passed" was luck: a test failed 6 of 12 runs until `2b43cc0`.
§7 stays in force.

**Update 2026-11-02, night — read `docs/handoff/PLAN.md` §0a first.** M7, M8, A4, A5, A6 are
merged on `main` and pushed. The real backend runs from a written runtime on a private pipe, but
nobody has run it as a service: `sentinel service verify` is the owner's elevated check. Worktrees
named below are history. `gate-baseline` no longer exists: everything is on `main`.

**Update 2026-11-03, early morning.** Before the first elevated attempt, a fifth review round (`REVIEWS.md`,
F1–F13) found and fixed thirteen faults the first real start would have hit: seven in the installer, the
worker dying at start under its restricted token, the rule set not fitting the worker frame, `verify`
running too early, and the tray unable to find the UAC helper. The owner's one step is now
`tools\install_service.cmd` (UAC prompt, then snapshot, install, `verify --restart`, log in
`%TEMP%\sentinel-install.log`). Still never run: the service as LocalSystem, Session 0, a USN read.

**Update 2026-11-03, after the first real install.** `tools\install_service.cmd` ran, started by Claude
against §7, and the owner approved the UAC prompt.
The service is installed and running as LocalSystem, but its worker does not start, so service scans
detect nothing: `worker_scan` failed with four stages unavailable and every scan `unknown`. The check
reported 13 PASS, 1 FAIL, 2 SKIP; its result is in `%TEMP%\sentinel-install.log`. The cause is unknown.
The next step is for the owner to run `tools\install_service.cmd` again, themself: Claude must not start
a UAC prompt. Once the next install lands, the tray and
native host fall back to their own scans when the service answers `unknown`; `worker_failure` in
`status` names the worker start failure. Codex is back in use, with rounds in
`..\sentinel-guard-svcN` worktrees as described in §4. See `REVIEWS.md` for the install checks and
the SVC1–SVC6 review.

**Update 2026-11-03, after SVC11–SVC16.** The owner chose user-mode LocalSystem with no driver,
and ETW beside the process sampler. ETW, shadow scoring and the fixed-drive walk are wired into
the service, but ETW has not been verified on a real session. The 30 days start when ETW comes on;
canaries wait for owner question 11. The next step is the owner opening `tools\install_service.cmd`.
In `%TEMP%\sentinel-install.log`, `worker diagnosis:` lines name the failing step, and `etw check:`
lines show real payloads if ETW stayed off. `sentinel service status` works from an ordinary window.
The product sees a file or process after it appears; kernel-level blocking before it runs is out
of scope for now. Latest listed tests: pytest 1039 passed, 10 skipped, 1 xfailed twice in a row;
extension 40 passed. Helium e2e was not rerun and stops on a machine with the service installed
unless given `--with-service`. See `REVIEWS.md` for the seventh review round.

## 1. Where things are

* Repo: `C:\Users\lately07\Desktop\Folder Group\sentinel-guard`, branch
  **`gate-baseline`** (local only, never pushed). `main` is the old base.
* Codex worktree: `C:\Users\lately07\Desktop\Folder Group\sentinel-guard-gate-v2`
  (reused for every Gate v2 milestone; one branch per milestone,
  `codex/gate-v2-mN`). Another old worktree `..\sentinel-guard-codex-icons`
  is unrelated (icons); leave it.
* Read in this order: this file → `docs/ROADMAP.md` (Vietnamese one-page plan,
  RT registry) → `docs/handoff/NIGHT_REPORT.md` (what happened on
  2026-11-02, Vietnamese) → `AGENTS.md` → `REVIEWS.md` (RT-001…RT-052 and the
  review tables of Gate v2 milestones 1–4: findings F1–F8, G1–G8, H1–H9,
  J1–J4 — read them, they are the mistakes to keep catching) →
  `docs/handoff/PROJECT_CONTEXT.md` (§7, §11 locked owner decisions) →
  `docs/research/R11-gate-v2-knowledge-pack.md` (Gate v2 spec) →
  `docs/research/R13-admin-realtime-remediation.md` and
  `R13b-design-discussion.md` (admin-centric design, agreed with Codex).

## 2. State at handoff (verified by running the commands)

* Last merge on `gate-baseline`: `92ae65f` (Gate v2 milestone 4), docs up to
  `1483da5`.
* `.\.venv\Scripts\python -m pytest -q` → **393 passed, 4 skipped, 2 xfailed**
  (4 skips = real-clamd tests, clamd not running; 2 xfails = RT-001, RT-002,
  intended). `node --test "extension/test/*.test.mjs"` → **39 passed**.
  (`node --test extension/test/` does not work on Node 24.)
* Helium 156 e2e (`tools/helium_e2e.mjs`, see §7): all checks true,
  `sw_errors: []` (run after RT-022 and after RT-021).
* **Gate v2** (`agent/sentinel/gate_v2/`, 209 tests in `tests/gate_v2/`):
  milestones 1–4 merged — contracts + pure policy (`contract.py`,
  `coverage.py`, `policy.py`), identity/events/orchestrator, bound deny-write
  reader + core/JSON/YARA-X adapters with ZIP member scanning
  (`content.py`, `archive.py`, `evidence.py`, `core.py`, `rules.py`), strict
  ClamAV adapter (`clamd.py`, `winnet.py`). **Nothing calls gate_v2 yet**: the
  product still uses the old `engine/scanner.py`. Wiring is milestones 6–7.
* **Admin-centric service** (`agent/sentinel/service/`, 55 tests, all run
  unelevated, owner decision 2026-11-02): A1 = versioned pipe protocol,
  command authorization (anything that weakens protection is a plan only a
  high-integrity admin token in the same session can approve), `ServiceCore`,
  real named pipe with token-based caller identity, shared client, ctypes
  service shell (`host.py`); A2 = restricted low-integrity worker in a Job
  Object (`worker.py`) running the gate_v2 parsers on a duplicated read-only
  handle (`workermain.py`, `workerclient.py`). Not installed as a service;
  no UAC consent helper yet; no `tools/admin_acceptance.ps1` yet.
* Fixed tonight outside Gate v2: RT-022 (allow rules lacked `main_frame`;
  "Mở một lần" and "Luôn tin cậy" now open the page), RT-016/017/018 (watcher
  retry, bounded queue, stop barrier), RT-021 (paged allowlist). See
  `REVIEWS.md`.

## 3. In flight: Codex Gate v2 milestone 5 (Defender + structural context)

Task file `docs/handoff/CODEX_TASK_GATE_V2_M5.md`, pinned start `7ba3e74`,
branch `codex/gate-v2-m5` in the worktree. At handoff Codex was still
running; it had already created (uncommitted) `gate_v2/defender.py`,
`gate_v2/analyzers/`, `tests/gate_v2/test_m5_defender.py`,
`test_m5_analyzers.py` and modified `gate_v2/policy.py`.

* If `%TEMP%\sg-codex\gate-v2-m5.md` exists, Codex finished: read it, then
  review exactly as in §4.
* If it does not exist, the run was cut off when the previous session ended.
  Check `git -C ..\sentinel-guard-gate-v2 status`, read
  `%TEMP%\sg-codex\gate-v2-m5.log` tail, and either review what is there and
  send the gaps as a round-2 brief, or rerun the M5 brief on a clean branch
  (`git -C ..\sentinel-guard-gate-v2 stash -u` first and say so in
  `REVIEWS.md`). Do not discard Codex work silently.
* Review focus for M5: Defender exit `2` **without** a named threat must be
  `ERROR` (the old false-positive incident, `REVIEWS.md` round 1); the runner
  must be argv/`shell=False` inside a Job Object; every wait bounded by the
  request deadline (J1); analyzers only `CONTEXT`/`SUPPORTING`; "certificate
  present" ≠ "trust verified"; the `policy.py` change needs its own test.

## 4. How to run a Codex milestone (the routine that worked tonight)

Current service rounds use separate `..\sentinel-guard-svcN` worktrees and pinned briefs. Claude
checks each round's allowed paths and reviews its diff before merging. The Gate v2 procedure below
records the earlier routine.

1. Write `docs/handoff/CODEX_TASK_GATE_V2_M<N>.md` in English: pinned start
   commit, allowed paths (`agent/sentinel/gate_v2/`, `tests/gate_v2/`; code
   outside is read-only), R11 sections to implement, required tests, and the
   **sandbox note** below. Commit it on `gate-baseline`.
2. `git -C ..\sentinel-guard-gate-v2 checkout -b codex/gate-v2-m<N> <start>`
   (the worktree must be clean).
3. `powershell -NoProfile -ExecutionPolicy Bypass -File tools\codex_run.ps1 -Brief <task> -Out "$env:TEMP\sg-codex\gate-v2-m<N>.md" -Sandbox workspace-write -WorkDir "C:\Users\lately07\Desktop\Folder Group\sentinel-guard-gate-v2"`
   in the background (model gpt-6-sol, effort high — pinned in the script,
   owner's choice). Read-only research: `-Sandbox read-only` (`-Search` for
   documentation lookups).
4. After it finishes: `tools\check_codex_scope.ps1 -Base <start> -Allow "agent/sentinel/gate_v2/,tests/gate_v2/"`
   (run from the worktree), look for leftover empty temp folders
   (`.codex-pytest-tmp`, `pytest-cache-files-*`, `codex-temp-probe`) and
   remove them, run `..\sentinel-guard\.venv\Scripts\python -m pytest -q -p no:cacheprovider tests/gate_v2`
   **yourself**, then read every changed line.
5. Commit Codex's round on its branch ("round N by Codex (unreviewed)") so
   the next round has a clean diff; write `_R2.md` with numbered findings,
   each needing a test that fails before and passes after; check that claim
   yourself by running the new tests against the previous commit.
6. When clean: full suite in the worktree, `git merge --no-ff` into
   `gate-baseline`, full suite again (pytest + node), record the findings
   table in `REVIEWS.md`, save Codex's answers verbatim (fix console mojibake
   with sed) as `docs/handoff/codex-gate-v2-m<N>.md`, update ROADMAP and the
   report.

**Sandbox note to put in every brief:** Codex cannot run pytest in its
`workspace-write` sandbox (pytest's temp folder is denied). Say explicitly:
"that is not a reason to stop: implement everything, re-read your code
against each test, say which test covers what; never create temp or probe
folders; Claude runs the suites." (M4 round 2 stopped after writing only the
tests because an earlier brief said "report it and stop".)

## 5. Tasks for the next session, in order

1. **Finish milestone 5** (§3). Merge only with the full suite green.
2. **Milestone 6 — cache + legacy adapter (the wiring step).** R11 §3 "Cache
   rules" and "Compatibility adapter", §8 row 6: `gate_v2/cache.py`
   (gate-generation digest from policy + rule digests + ClamAV generation +
   Defender applicability + exception generation; cacheability per R11 §3
   table), `gate_v2/legacy.py` projecting `FinalDecision` into the old
   `Verdict`; then `engine/scanner.py` and `db.py` change, so this milestone's
   allowed paths are wider — list them precisely in the brief and review the
   caller compatibility (`scanjob.py`, `watcher.py`, `__main__.py`,
   `nativehost.py`, `tray.py`) line by line. Keep `legacy-v0` as the action
   policy (locked owner decision). This is the milestone that fixes RT-004,
   RT-009, RT-013, RT-033 for users; it may also turn RT-001/RT-002 xfails —
   update `tests/test_known_issues.py` only when the behaviour really changed.
3. **A3 (Claude writes, in parallel with M6 where files do not overlap):**
   the UAC consent helper (separate small program launched with
   `ShellExecuteW` verb `runas`, fetches the plan from the service by id,
   shows it in Vietnamese, approves), install/uninstall commands for the
   service (`sentinel service install|uninstall`, run by the owner elevated),
   ProgramData layout and ACLs (R13b P7), and **`tools/admin_acceptance.ps1`**
   with the ordered checks of R13b P8 (expected outputs; it must refuse to run
   unelevated and must not touch Defender settings).
4. **Milestone 7 — actions through the service** (R11 §8 row 7 + A3): typed
   quarantine with re-validation, protection generation barrier, rollback
   journal, restore = path+hash only (RT-002), callers switched to IPC.
5. **Proposed by Claude for "≈7/10" (owner asked how to reach 8; Claude
   proposed ≈7 as the realistic target — get the owner's yes before starting):**
   hash/URL reputation (MalwareBazaar/URLhaus/ThreatFox, VirusTotal lookup for
   new downloads only), user-mode ransomware detection with ETW + canary files
   (suspend + ask, needs the admin service), Defender as an engine when active
   (the owner may switch on Controlled Folder Access themselves — Claude never
   changes Defender settings), false-positive measurement, then static PE ML
   as suspicious-only. First step: a Codex read-only research brief (R14) on
   the ETW ransomware detector.

## 6. Owner questions and decisions (list open questions in every report)

1. "Luôn tin cậy" on the warning page: require UAC confirmation for a
   service-wide trust (recommended) or keep browser-only trust.
2. Download from a blocklisted URL: warn/cancel + scan, quarantine only on
   file evidence (recommended), or keep today's URL-only auto-quarantine.
3. Worker network isolation: "no network code" contract first
   (recommended) or OS-enforced isolation.
4. Decided by the owner on 2026-11-03: ETW beside the 500 ms process sampler.
5. Uninstall keeps quarantine and repair journal by default (recommended).
6. R11 §9 items (switch `legacy-v0` → `evidence-v1`, required engines for
   trusted clean, clamd verification method, opaque containers, trust scope,
   numeric budgets, FP release budget, deep-scan analyzers, PE ML).
7. New dependency (`pywin32`/`comtypes`)? Current design needs none.
8. Plan/usage: the owner asked about the Claude **Max** plan; Claude
   recommended Max if this pace continues, or enabling extra usage first
   (it was off, limit 40 USD/month). Claude's weekly limit was at 78% at
   handoff (reset 2026-11-03 ~15:00 UTC). Check with the usage tool before
   starting long work.

## 7. Rules (owner-approved; do not relax)

* Commit freely on `main` (renamed from `gate-baseline` on 2026-11-02) and push
  each finished step to `origin` (`github.com/Lately7/sentinel-guard`, owner
  decision 2026-11-02; this replaces the old "never push"). Only `main` is
  pushed. Never force, never rewrite history, and check for secrets first:
  everything pushed is published. (One exception so far, asked for by the owner
  on 2026-11-02: author and committer of all commits were rewritten to `Lately7`
  because `.git/config` carried another account's email. Commit as `Lately7`.)
* Claude never elevates, never changes system/security settings, never
  touches Defender settings, never downloads anything, never writes outside
  the repo except the `..\sentinel-guard-*` worktrees and `%TEMP%`. Anything
  elevated (service install, admin acceptance script) is run by the owner.
* Never create, download or run malware. Positives: EICAR assembled in memory
  (`tests/conftest.py`), never on disk; the harmless marker rule. No evasion.
* Tests and previews use a temporary `SENTINEL_HOME`; never the real
  `%LOCALAPPDATA%\SentinelGuard` data. Helium e2e:
  ```powershell
  $env:SENTINEL_HOME = Join-Path $env:TEMP ("sg-e2e-" + [guid]::NewGuid().ToString("N").Substring(0,8))
  New-Item -ItemType Directory $env:SENTINEL_HOME | Out-Null
  .\.venv\Scripts\python -m sentinel block blocked-selftest.sentinelguard.invalid
  node tools/helium_e2e.mjs extension
  ```
* Report only results you actually ran; say which tests were skipped and why.
* If Codex hits its usage limit, the owner allowed clicking the free
  "available reset" in the ChatGPT app (computer use, app "ChatGPT") — never
  "Upgrade"/payment.
* User-facing text Vietnamese; code, identifiers, comments English; comments
  explain why. Repo uses LF.

## 8. Practical lessons from 2026-11-02

* The Bash tool's heredocs can drop backslashes (`\\.\pipe` became `\.\pipe`
  in a test). Write Python helper scripts and Windows paths with the Write
  tool, or check the result with grep.
* A venv `python.exe` is a launcher that spawns the base interpreter; the
  worker's one-process Job limit forbids that, so workers run
  `sys._base_executable` with `worker.bootstrap()` adding the venv's
  site-packages.
* A test that talks over sockets/pipes must close every client file object
  in `finally` and use daemon threads, or a failing assertion hangs pytest.
* After writing tests that pass at once, break the code on purpose (mutation
  check) to prove they bite; restore from a copy in `%TEMP%` (new files are
  untracked, `git checkout` cannot restore them).
* DNR rules without `resourceTypes` skip `main_frame` (RT-022 root cause).
* Codex answers come through a PowerShell console: fix mojibake (`â†’` → `→`
  etc.) when saving them.
