You are the independent security reviewer for Sentinel Guard, the repository
owner's own Windows 11 anti-malware prototype (Python agent + MV3 browser
extension) in the current directory. This round is defensive design research,
read-only: do NOT modify, create or delete any file in the repository.

Read first: docs/handoff/PROJECT_CONTEXT.md (sections 4, 7, 10, 11 and 12 are
binding; decisions in sections 7 and 11 are locked, do not re-argue them),
AGENTS.md, README.md, agent/sentinel/engine/clamav.py,
agent/sentinel/engine/scanner.py, agent/sentinel/engine/verdict.py,
agent/sentinel/protection.py, agent/sentinel/watcher.py.

The owner's goal: Sentinel uses ClamAV as its layer 3. The owner wants to know
where ClamAV is weak as a Windows endpoint engine and how Sentinel should cover
those gaps, informed by how two commercial products (Bitdefender and
Malwarebytes) structure their protection. You may use web search for public
vendor documentation, whitepapers, patents, independent test-lab reports
(AV-TEST, AV-Comparatives, SE Labs, MRG Effitas) and ClamAV's official docs.

## Part A — ClamAV coverage gaps, as Sentinel uses it

1. What ClamAV is and is not good at on Windows endpoints: signature types
   (hash, body, logical, bytecode, YARA subset), unpacking support, heuristics,
   detection of new/unknown Windows PE malware, false positives, speed, update
   cadence. Cite public evidence; mark where data is old or missing.
2. Review Sentinel's own clamd configuration in
   `agent/sentinel/engine/clamav.py` `write_configs()` line by line against the
   official `clamd.conf` documentation for ClamAV 1.5: options that are wrong,
   missing, weaker than needed, or that hide incomplete scans (for example the
   `Alert*` switches, `MaxScanSize`/`MaxFileSize`/`MaxRecursion`/`MaxFiles`
   versus what the agent reports as coverage, `HeuristicScanPrecedence`,
   `PhishingSignatures`, `StructuredDataDetection`, `DetectPUA`).
3. How Sentinel interprets ClamAV results (`clamav.py`, `scanner.py`): what a
   ClamAV "OK" really proves, which names are weak evidence, and where a gap in
   ClamAV currently turns into a false "clean" in Sentinel. Reuse RT ids from
   PROJECT_CONTEXT.md section 9 and codex-review-r4.md; new issues get RT-012+.
4. Additional public signature sources usable with ClamAV (official and
   third-party), with licence and update constraints.

## Part B — How Bitdefender and Malwarebytes protect a Windows endpoint

From public material only, describe each product's protection layers and how
they cooperate: pre-execution (signatures, static machine learning, cloud
reputation, emulation/sandbox), on-execution (behaviour monitoring, process
scoring, anti-exploit, anti-ransomware, rollback/remediation), web/email
protection, and what each layer needs from the operating system (kernel
driver, minifilter, ETW, AMSI, elevated service). Name the vendor's own terms
(for example Bitdefender Global Protective Network, Advanced Threat Defense,
HyperDetect; Malwarebytes Katana engine, Anti-Exploit, Anti-Ransomware) and
cite a source for each claim. Separate documented fact from your inference.
Describe architecture and concepts only; no reverse engineering, no proprietary
code, and nothing about defeating or bypassing these products.

## Part C — Recommendations for Sentinel

A ranked table (highest value first). For each item: the ClamAV gap it covers,
the commercial-product idea it borrows, what is feasible for a user-mode Python
agent without a kernel driver or admin rights (say so plainly when something
is not feasible), expected false-positive risk, effort (S/M/L), which existing
module it touches, where it fits in the plan in PROJECT_CONTEXT.md section 8
(C3x, Contract v1, quarantine hardening, smart scan) or after it, and the
harmless synthetic test that would prove it works. Include quick wins in the
clamd configuration separately from larger features.

## Safety and limits (non-negotiable)

- Read-only in the repository. No downloads of malware samples, no executing
  anything you fetch. Defensive research only: do not describe evasion,
  bypass, persistence, credential theft, or disabling security software.
- Do not touch Microsoft Defender settings or any system security setting.
- Never claim a command ran unless you ran it and saw the result.

Answer in English, as Markdown, concise and concrete, with file:line for code
claims and a source URL for every external claim. End with a "Sources" list.
