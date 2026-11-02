# R9 — How Malwarebytes and the major antivirus products decide, in depth

Use web search. Public material only: vendor documentation, help centres,
engineering blogs, whitepapers, patents, conference talks, independent
test-lab methodology (AV-TEST, AV-Comparatives, SE Labs, MRG Effitas), and
reputable third-party analyses. No reverse engineering, no proprietary code.

## Products

Malwarebytes (deepest: consumer Windows, Browser Guard, ThreatDown/EDR where
it explains the engine), Microsoft Defender Antivirus (+ MAPS cloud,
block at first sight, ASR rules, AMSI, network protection, tamper protection,
Smart App Control), Bitdefender, Kaspersky, ESET, Sophos (Intercept X).

## For each product

1. **Pipeline.** Every layer in order: pre-execution (hash, signatures,
   generic/heuristic rules, emulation/unpacking, static ML, cloud lookup,
   reputation/prevalence, certificate checks), on-execution (behaviour,
   memory scanning, exploit mitigation, ransomware protection), post-event
   (remediation, rollback), web/browser. Vendor term for each.
2. **Decision policy.** How evidence from several layers becomes a verdict;
   thresholds, confidence, "suspicious" vs "malicious", PUP/PUA handling,
   what happens on a weak single signal, how false positives are prevented
   (allowlists, signer trust, prevalence, FP feedback loops).
3. **Action policy.** Block, quarantine, ask, notify; what is automatic;
   restore and exclusions semantics; how remediation finds related artifacts
   (registry, scheduled tasks, services, dropped files).
4. **Failure modes.** What the product does when the cloud is unreachable,
   a scan times out, a file is too big or encrypted, an engine crashes, or
   the definitions are stale. Does it ever report "clean" without having
   inspected the file?
5. **Scan types.** Exactly what quick/threat/full/custom/deep/boot-time scans
   enumerate (memory, startup, registry, services, tasks, browser data,
   rootkit checks) and their time budgets.
6. **Naming.** Detection-name conventions and what a name reveals about
   detection type and confidence (e.g. Malwarebytes `Generic.Malware/Suspicious`,
   `MachineLearning/Anomalous`, `Malware.AI`; Defender `!ml`, `!MTB`, `!rfn`).

## Then

A cross-product comparison table, and "Design lessons for Gate v2 in a
user-mode Python agent": what to copy, what cannot be copied without a
driver/cloud, and the exact verdict/action rules you recommend, consistent
with the locked decisions in PROJECT_CONTEXT.md §7 and §11.
