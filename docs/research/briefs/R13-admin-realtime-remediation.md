# Codex research round R13 — elevated architecture, real-time protection, downloads, scan / deep scan / scan-and-repair

Read-only research round. Do not modify any file. Answer in English; Claude
saves your answer as `docs/research/R13-admin-realtime-remediation.md`.

## Context

Sentinel Guard is the repository owner's own Windows 11 anti-malware
prototype (Python agent in `agent/sentinel/`, MV3 extension in `extension/`,
Gate v2 being rebuilt under `agent/sentinel/gate_v2/` from your spec
`docs/research/R11-gate-v2-knowledge-pack.md`). Read first:
`docs/handoff/PROJECT_CONTEXT.md` (§§7, 10–12), `docs/ROADMAP.md`,
`REVIEWS.md`, R11, `docs/research/R12c-osquery.md`, `R12d-wazuh.md`, and the
current code: `watcher.py`, `scanjob.py`, `quarantine.py`, `protection.py`,
`nativehost.py`, `install.py`, `tray.py`, `engine/`.

**New owner decision (2026-11-02, night):** the application should run with
administrator rights and be designed around them, real-time protection must be
optimised, downloaded files must be checked thoroughly, and the scan, deep
scan and "scan and repair" (remediation) functions need research. Until now
the design assumed a no-admin agent (R11 §1 "Watch events are hints", R12d
who-data note, PROJECT_CONTEXT §12). There is still **no kernel driver**
(no signed minifilter, no ELAM/PPL) — say where that limit bites.

## Questions

1. **Elevated architecture.** Compare (a) a Windows service (LocalSystem vs.
   LocalService/virtual account with specific privileges), (b) a scheduled
   task "run with highest privileges" at logon, (c) an elevated tray app via
   UAC. For each: start-up before logon, per-user UI, how the browser native
   host (always launched unelevated by the browser) and the tray talk to the
   privileged part (named pipe ACLs, caller identity checks, message
   validation), and the privilege-escalation risks specific to a **Python**
   agent: writable install directory, `site-packages`, `.pyc`, DLL search
   order, `%PATH%`, `SENTINEL_HOME` / data directory ACLs, update path.
   Recommend one, with the minimum privileges it needs.
2. **Parsing untrusted files while privileged.** How to keep archive/PE/
   YARA-X/ClamAV-client parsing out of the privileged process: a low-privilege
   worker (restricted token, low integrity, AppContainer, Job Object limits),
   what each blocks, and the cost for Python. Which operations truly need the
   privileged side (quarantine of files the user cannot write, ACL'd
   quarantine store, reading other users' profiles, process termination,
   registry/service/task repair).
3. **Real-time protection with admin rights and no driver.** What becomes
   possible and what it is worth: USN change journal (`FSCTL_READ_USN_JOURNAL`)
   for gap-free change tracking and reconciliation after watcher overflow
   (our RT-017 follow-up); ETW real-time sessions (Kernel-Process /
   Kernel-File / image-load providers) or WMI process-start traces to scan a
   process image at start; Security-log auditing (SACL + 4663, Wazuh
   who-data, R12d) for writer attribution; watching all fixed volumes vs.
   chosen folders; event rates and CPU cost; what still cannot be done before
   execution without a minifilter. Give a concrete design for Sentinel with
   bounded queues, priorities (executables/scripts/archives first) and the
   R11 invariants.
4. **Downloaded files.** Mark-of-the-Web (`Zone.Identifier` ADS: `ZoneId`,
   `HostUrl`, `ReferrerUrl`) reading and its trust limits, MotW propagation
   into extracted archives, scan on download completion vs. on first
   execution, browser-independent detection of downloads (Helium, Chrome,
   Edge, Firefox), re-scan when signatures update, and how the extension's
   `scan_download` path should change once the agent is privileged.
5. **Scan and deep scan with admin.** What an elevated smart scan and deep
   scan should cover (all user profiles, services `ImagePath`, drivers list,
   all Task Scheduler folders through COM, WMI event-consumer persistence,
   IFEO/AppInit/Winlogon/COM hijack keys — the Autoruns categories —,
   browser extensions of every profile, `hosts` file, running process images
   and modules, optional process-memory scan with YARA-X), budgets and
   coverage reporting per R11 (source-entry coverage, denied entries).
6. **Scan and repair (remediation).** What "repair" should mean for
   Sentinel: terminate a process tree, quarantine, remove persistence entries
   (Run/RunOnce, services, scheduled tasks, WMI consumers, IFEO), restore a
   tampered `hosts` file, delete-on-reboot (`MoveFileEx`
   `MOVEFILE_DELAY_UNTIL_REBOOT`) for locked files, and a **rollback journal**
   for every step. Safety rules: never touch Windows-protected files,
   signed Microsoft components or Defender settings; confirmation levels;
   conclusive evidence only for automatic repair (R11 action policy); how
   commercial products (Defender remediation, Malwarebytes, Autoruns as a
   manual tool) describe this publicly. No evasion, no exploitation.
7. **Impact on locked decisions and Gate v2.** Which R11 invariants and
   PROJECT_CONTEXT decisions change, proposed new invariants (privilege
   separation, IPC authentication, repair rollback), and where new milestones
   fit into the R11 §8 plan (milestones 1–2 exist; do not redesign them).

## Rules

Read-only. Cite sources (file:line for this repo; official Microsoft or
vendor documentation URLs for Windows behaviour; you may use web search for
documentation only, never to download software or samples). Mark proposals
as **Proposal** and facts with their source. Harmless, defensive scope only:
no malware, no evasion or anti-analysis techniques, no disabling of security
products. Be concrete: data structures, API names, privileges, limits, test
plans with harmless synthetic inputs, and an ordered implementation plan
with acceptance checks Claude can run without admin rights where possible
(and a list of checks that need the owner to run something elevated).
