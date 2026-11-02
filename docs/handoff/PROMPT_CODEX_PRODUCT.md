You are a research scientist reviewing Sentinel Guard, the repository owner's
own Windows 11 anti-malware prototype (Python agent + MV3 browser extension for
the Helium browser) in the current directory. Read-only: do NOT modify, create
or delete any file. You may use web search for public documentation and
design references.

Read first: docs/handoff/PROJECT_CONTEXT.md (sections 7 and 11 are locked
decisions; do not re-argue them), docs/handoff/codex-review-r4.md and
docs/handoff/codex-research-r5.md (your earlier rounds; build on them, do not
repeat them), AGENTS.md, README.md. Then the code: agent/sentinel/ (scanner,
engines, watcher.py, scanjob.py, protection.py, quarantine.py, nativehost.py,
theme.py, gate_ui.py, tray.py) and extension/ (manifest.json, src/*.js,
src/*.html, src/ui.css). The attached image is the current dashboard
(dark theme, rendered with harmless demo rows).

The owner requires at least three product features, and wants useful
additions beyond them:
1. Scan / Deep scan (on demand)
2. Browser protection extension for Helium
3. Real-time protection

## Part 1 — Overview of the logic as built

Short map of how each of the three features works end to end today (entry
point -> engines -> verdict -> action -> UI/log), with file:line. State plainly
what each feature does NOT do. Note anything the README claims that the code
does not deliver.

## Part 2 — Compare with mainstream antivirus products

For each of the three features, compare Sentinel with how Microsoft Defender,
Bitdefender, Malwarebytes (and, for the browser part, Malwarebytes Browser
Guard, Bitdefender TrafficLight, Google Safe Browsing / Microsoft SmartScreen)
structure the same capability, from public material with a source per claim.
Focus on scan modes (quick / smart / full / custom / deep: what each one
covers), real-time triggers, and browser protection signals. Separate
documented fact from inference.

## Part 3 — Logic defects and weaknesses

New defects only (reuse existing RT ids where it is the same issue; new ones
start at RT-016). For each: id, title, severity, file:line, harmless
reproduction, the test that would prove it, suggested direction. Cover in
particular: the extension's message validation and native-messaging bridge,
blocklist/allowlist handling and the "proceed anyway" flow, download scanning
handoff, the watcher's event handling and debouncing, scan-job traversal
(junctions, long paths, locked files), and the UI showing a result that the
engine did not establish. Defensive review of this project's own code only:
no evasion techniques, no instructions for defeating any product.

## Part 4 — Feature plan

A. What "Deep scan" should mean for Sentinel versus "Scan" (scope, which
   layers, limits, archive depth, time budget, how partial coverage is shown),
   consistent with the locked smart-scan design in PROJECT_CONTEXT.md section 10.
B. Real-time protection: what is achievable without a kernel driver or admin
   rights, and what must be stated as a limitation.
C. Helium extension: gaps and improvements.
D. Up to 8 additional useful features, ranked by value to a home user versus
   effort and false-positive risk (for example: scheduled scans, scan history,
   exclusions UI, startup-item review, USB/removable drive scan on insert,
   download reputation, report export). For each: feasibility in user-mode
   Python, effort S/M/L, where it fits in the plan, and a harmless test.

## Part 5 — UI and animation review: make it look less AI-generated

Look at the attached screenshot and the UI code. Be specific and opinionated:
- What in the current layout, copy, colour, spacing, typography and motion
  reads as generic or "AI-made", and what a careful human product designer
  would do instead (cite real products whose security UI is well regarded).
- Concrete changes: exact layout of the main screen for the three features,
  information hierarchy, which text to remove or shorten (Vietnamese UI text),
  numbers and status words, empty states, error states.
- Motion: which of the current animations (fading status dots, breathing dot
  while ClamAV starts, sliding 2px activity bar, sweep line across the logo,
  row flash on new results) to keep, change or drop, with timing/easing values
  and a reason. Motion must stay subtle and purposeful.
- The logo: a small black square easing to grey inside a thin outline. Is it
  legible at 16 px in the tray on light and dark taskbars? What would you
  change?
Constraints: Tkinter/ttk on Windows (no web view), dark theme, compact, crisp.

## Rules

- Read-only. Never claim a command ran unless you ran it and saw the result.
- No malware samples, no downloads of samples, no evasion or bypass content.
- Answer in English, Markdown, concise and concrete, file:line for code
  claims, a source URL for every external claim, "Sources" list at the end.
