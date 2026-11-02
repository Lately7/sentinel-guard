# Codex research round R14 — user-mode ransomware detection with ETW and canary files

Read-only research round. Do not create, modify or delete any file. Answer in
English; Claude saves your answer as `docs/research/R14-etw-ransomware-detection.md`.

## Context

Sentinel Guard is the repository owner's own Windows 11 anti-malware prototype.
There is no kernel driver and there will not be one (no EV certificate, no
attestation signing, no ELAM/PPL). The design: a thin LocalSystem service written
with `ctypes`, an unelevated tray, and a restricted scan worker. Read first:
`docs/ROADMAP.md` ("Đề xuất: mục tiêu ≈7/10"), `docs/research/R13-admin-realtime-remediation.md`,
`docs/research/R13b-design-discussion.md` (P1, P2, P6), `docs/research/R10-malware-file-gate.md`,
`docs/handoff/codex-literature-r7.md`, `agent/sentinel/service/`, `agent/sentinel/watcher.py`.
Do not repeat them; go deeper.

**Goal.** Decide whether a user-mode detector can stop an ordinary encrypting
process early enough to matter, on one owner's PC, with very few false alarms, and
specify it precisely enough to implement. The intended response is to suspend the
process and ask the user. Claude never changes Defender settings; the owner may
switch on Controlled Folder Access themselves.

## Questions

1. **Signal sources without a driver.** Compare each on latency, data available,
   privilege, loss behaviour and CPU cost: ETW `Microsoft-Windows-Kernel-File`,
   `Microsoft-Windows-Kernel-Process`, NT Kernel Logger file I/O flags; USN journal;
   `ReadDirectoryChangesW`; canary-file handles. State which providers are not
   available to an ordinary service (for example Threat-Intelligence and PPL
   requirements). Exact keywords, event ids and fields, including how to attribute
   a file write to a process and how reliable that attribution is.
2. **`ctypes` ETW consumer in Python.** `StartTrace`, `EnableTraceEx2`, `OpenTrace`,
   `ProcessTrace`, callback mechanics, GIL cost, event rates seen on a busy desktop,
   `EventsLost`/`RealTimeBuffersLost` handling, session name collisions, cleanup after
   a crash, and the 64-session limit. Is an in-process Python callback viable, or is a
   small helper needed? Give numbers or say that none exist and how to measure them.
3. **Canary files.** Placement, naming, type mix, ACLs, how many, how they avoid
   backup/sync/indexer noise, how a file-walking encryptor reaches them, and how an
   encryptor that skips them is handled. What published work says about the rate of
   evasion by ordering, in defender terms only.
4. **Behavioural scoring.** Published signals (write entropy, read-then-overwrite,
   rename and extension churn, file-type change, directory sweep rate). Summarise
   UNVEIL, CryptoDrop, ShieldFS, RWGuard, Redemption and later work: method, data,
   measured false positives, and how those numbers were obtained. Which signals are
   computable from what question 1 provides, without reading file content in the
   privileged process? Entropy needs bytes: where may that run under R13b P4?
5. **False positives.** Enumerate legitimate workloads that resemble encryption: 7-Zip,
   backup tools, OneDrive, game launchers, git, package managers, video encoders,
   BitLocker, EFS, installers, IDEs. How should each be told apart, with no allowlist
   that malware can trivially satisfy (for example a signed binary is not sufficient)?
6. **Response.** `NtSuspendProcess` versus suspending threads: rights required, effect on
   process trees and child jobs, risk of suspending something critical, and which targets
   are never touched (protected processes, Windows components, other security products).
   Bounded prompt design when the user is away. How many files are lost in the worst
   case before the suspend lands, as a function of signal latency. VSS: what a user-mode
   service can do, and why this project must not delete or alter shadow copies.
7. **Measuring without malware.** The project never creates, downloads or runs real
   malware. Specify a harmless simulator: a benign program, confined to a disposable
   directory, that reproduces the file-operation pattern (read, encrypt with a fixed
   test key, overwrite or rename) so that detection latency and false-negative rate
   can be measured, plus a replay method for recorded benign workloads to measure false
   positives. What such a simulator can and cannot show.
8. **Comparison.** What Microsoft Controlled Folder Access, Malwarebytes Ransomware
   Protection and Bitdefender Ransomware Remediation publicly document. Only documented
   claims, with URLs.

## Deliverable

A verdict first: build, build a reduced version, or do not build, with reasons. Then:
the chosen design; exact API sequence; state machine; thresholds marked as hypotheses to
measure; data structures with bounds; failure and degradation behaviour (dropped events
must be reported as coverage gaps, never hidden); test plan using the simulator; ordered
milestones with honest size estimates; what must be measured on the owner's machine
before each step. Separate documented fact from inference; cite a URL for every external
claim and `path:line` for every code claim; say what would settle each uncertainty.

## Rules

Never claim a command ran unless you ran it and saw the result. No malware samples, no
sample links, nothing that helps anyone evade a security product; describe detection logic
and its gaps at the level a defender needs. Long is fine; padding is not.
