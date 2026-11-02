# Codex research — round 5: ClamAV gaps vs Bitdefender/Malwarebytes (read-only, web search)

Prompt: `docs/handoff/PROMPT_CODEX_RESEARCH.md`, `codex --search exec --sandbox read-only`, 2026-11-02.
Claude verified against the code: RT-012 (`AlertExceedsMax no`, clamav.py:108) and RT-013
(`Verdict.label` uses findings only, verdict.py:62-72; ClamAV unavailable/error returns no finding,
clamav.py:331-345) are confirmed. RT-014/RT-015 not yet reproduced. External claims are Codex's,
with its sources; not independently re-checked.

## Codex answer (verbatim)

# Independent security review

Scope: read-only review of the requested files and public documentation. I did not modify repository files, download samples, alter security settings, or run test suites.

## Executive assessment

ClamAV is a useful third scanning layer for Sentinel because it contributes a large known-threat signature set and substantially broader container/document parsing than Sentinel’s Python core. It is not a Windows endpoint-protection engine: its own Windows documentation says on-access prevention is Linux-only, it has no cloud service, and users wanting advanced endpoint detection should use a full endpoint suite. [ClamAV Windows FAQ](https://docs.clamav.net/faq/faq-win32.html)

The most important current problems are not simply ClamAV’s detection rate:

1. `AlertExceedsMax no` hides internal scan-limit exhaustion, so a partially inspected archive can produce `OK` and become `clamav: clean`. New issue: **RT-012**.
2. ClamAV errors/unavailability do not influence `Verdict.label`; a no-findings result remains globally `clean`. New issue: **RT-013**, closely related to RT-004.
3. Encrypted archives/documents can be opaque while producing `OK`. New issue: **RT-014**.
4. Almost every non-`Heuristics.*`/`PUA.*` name is immediately critical and potentially auto-quarantined: existing **RT-001**.
5. The watcher runs after filesystem events and cannot prevent execution. This is an inherent limitation of the no-driver, no-admin architecture, not something ClamAV configuration can solve.

The commercial-product lesson is not “add more signatures.” Bitdefender and Malwarebytes combine pre-execution classification with cloud/reputation or emulation, then use independent on-execution behavior, exploit and ransomware layers. Sentinel can reproduce evidence separation, coverage accounting, signer/reputation signals and limited notify-only anomaly detection in user mode. It cannot reproduce reliable pre-open blocking, process attribution, anti-exploit or protected rollback without privileged native components.

---

# Part A — ClamAV coverage gaps

## A1. What ClamAV does well and poorly on Windows

| Area | Assessment |
|---|---|
| Known/static malware | Strongest use. File hashes are exact and fast, but a one-byte change breaks a full-file hash. PE section hashes, body signatures and logical signatures offer progressively more generic matching. [Signature formats](https://docs.clamav.net/manual/Signatures.html), [hash-signature limitations](https://docs.clamav.net/manual/Signatures/HashSignatures.html), [logical signatures](https://docs.clamav.net/manual/Signatures/LogicalSignatures.html) |
| Body/logical matching | Body signatures support byte patterns, gaps and wildcards; logical signatures combine subsignatures and file/container metadata. These can recognize families rather than a single hash, but remain analyst-authored pattern detection. [Body format](https://docs.clamav.net/manual/Signatures/BodySignatureFormat.html) |
| Bytecode | Bytecode signatures execute constrained parsing/detection logic and can implement unpackers or complex file-specific detection. Disabling bytecode loses both detections and some unpacking support. [Bytecode documentation](https://docs.clamav.net/manual/Signatures/BytecodeSignatures.html) |
| YARA | ClamAV accepts `.yar`/`.yara`, but only a subset: no modules/imports, global rules, external variables or precompiled rules; maximum 64 strings; every rule needs a string. It may match normalized or decomposed content rather than the original bytes. Sentinel should continue using YARA-X separately and not assume YARA Forge rules will load equivalently in ClamAV. [ClamAV YARA limitations](https://docs.clamav.net/manual/Signatures/YaraRules.html) |
| Containers/documents | Valuable. ClamAV handles standard mail formats, ZIP, RAR, DMG, tar, gzip, bzip2, OLE2, CAB, CHM, Office, HTML, RTF and PDF. PE parsing can unpack recognized packers such as UPX, FSG and Petite. This is format-specific unpacking, not universal unpacking of arbitrary protectors. [ClamAV feature list](https://www.clamav.net/about) |
| New/unknown Windows PE malware | Limited compared with a full endpoint suite. Generic logical/bytecode signatures and file heuristics can catch variants, but there is no ClamAV cloud reputation, pre-execution ML service, process behavior scoring, exploit protection or ransomware behavior layer. ClamAV explicitly describes itself as a malware-detection toolkit rather than an endpoint suite. [Scanning documentation](https://docs.clamav.net/manual/Usage/Scanning.html), [Windows FAQ](https://docs.clamav.net/faq/faq-win32.html) |
| Windows real-time prevention | Absent from ClamAV itself. Its blocking on-access implementation uses Linux `fanotify`; the Windows build lacks that facility. Sentinel’s watchdog therefore detects after create/modify/move events and cannot hold the initiating open or process launch. [On-access documentation](https://docs.clamav.net/manual/OnAccess.html); local evidence: `agent/sentinel/watcher.py:53-101`, `README.md:112-120`. |
| False positives | ClamAV explicitly warns that false positives happen and recommends quarantine/copy rather than deletion. Its EOL policy says new signatures receive false-positive testing only on the latest patch of the latest feature release. [Alert interpretation](https://docs.clamav.net/faq/faq-scan-alerts.html), [EOL/testing policy](https://docs.clamav.net/faq/faq-eol.html) |
| Speed/resource use | `clamd` is the correct integration choice because `clamscan` constructs an engine and reloads the databases on every invocation. ClamAV recommends at least 3 GiB RAM on Windows; signature reload can temporarily require two engines. There is no current independent Sentinel-specific throughput measurement. [Scanning modes](https://docs.clamav.net/manual/Usage/Scanning.html), [system requirements](https://docs.clamav.net/), [reload memory](https://docs.clamav.net/manual/Installing/Docker.html) |
| Update cadence | Official sources are inconsistent: the CVD FAQ says usually once or twice daily, while the marketing page says multiple times daily. New submissions generally take at least 48 hours before a signature change is published. Sentinel checking every four hours cannot make new definitions appear faster than Talos publishes them. [CVD FAQ](https://docs.clamav.net/faq/faq-cvd.html), [ClamAV introduction](https://docs.clamav.net/) |
| Independent evidence | No current ClamAV Windows endpoint result was found from AV-TEST, AV-Comparatives, SE Labs or MRG Effitas. AV-TEST measured only 15.3% Windows-malware detection in a Linux scanner test in 2015; that result is eleven years old, used an obsolete engine and must not be presented as current performance. [AV-TEST 2015](https://www.av-test.org/en/news/linux-16-security-packages-against-windows-and-linux-malware-put-to-the-test/) |

A useful contrast, not a direct ClamAV comparison: AV-Comparatives’ March 2026 Windows test exercised execution and cloud/behavior layers. Bitdefender reached 99.94% protection with four false alarms; Malwarebytes reached 99.59% with 23. This demonstrates what the complete products deliver, not what any individual layer or engine delivers. [AV-Comparatives March 2026](https://av-comparatives.org/tests/malware-protection-test-march-2026/)

## A2. `write_configs()` against ClamAV 1.5.4

Reference: the tagged [ClamAV 1.5.4 Windows `clamd.conf` sample](https://raw.githubusercontent.com/Cisco-Talos/clamav/clamav-1.5.4/win32/conf_examples/clamd.conf.sample).

| Sentinel line | Assessment |
|---|---|
| `clamav.py:85` `DatabaseDirectory` | Correct and consistent with `freshclam`. Dynamic Windows paths should be quoted/escaped as in the official Windows sample. The present unquoted construction is fragile if a profile/data path contains spaces. **RT-015**; availability risk, not a silent clean while the daemon is down. |
| `:86` `LogFile` | Correct, with the same path-quoting concern. |
| `:87-89` log size/rotation/time | Valid. `LogRotate yes` is redundant because a nonzero `LogFileMaxSize` already enables rotation, but harmless. |
| `:90-91` loopback TCP | Valid. Binding only to `127.0.0.1` limits network exposure but does not authenticate a same-user process. Section 11’s clamd anti-spoofing decision remains locked and is not re-argued here. |
| `:92` `Foreground yes` | Correct for the owned subprocess. |
| `:93` `MaxThreads 4` | Reasonable and compatible with the planned two to three concurrent ClamAV requests. Client backpressure remains necessary. |
| `:94-95` read/command timeouts | Valid defaults/near-defaults. They bound socket inactivity, not the entire semantic coverage of a scan. |
| `:96` `StreamMaxLength 401M` | Correct for Sentinel’s maximum 400 MiB `INSTREAM` body plus margin. Exceeding this limit produces a protocol error, not a clean result. |
| `:97` `MaxScanSize 1600M` | Allows up to 1.6 GiB of recursively expanded data. It remains a hard coverage boundary. Sentinel currently cannot distinguish “all content scanned” from “stopped at this total.” |
| `:98` `MaxFileSize 401M` | Correctly prevents the 400 MiB outer stream from being silently skipped. It also limits each extracted inner file; a larger member may be skipped even though the outer stream is under 400 MiB. |
| `:99` `MaxRecursion 17` | ClamAV’s default. This is a necessary DoS bound, not full recursive coverage. |
| `:100` `MaxFiles 10000` | ClamAV’s default. Containers beyond this count are incomplete. |
| `:101` `MaxScanTime 120000` | Default two-minute bound. In 1.5’s sample it principally affects ZIP scanning. A timeout/limit event must become partial or unknown coverage, never clean. |
| `:102-103` parser flags | `ScanPE`, ELF, OLE2, PDF, SWF, HTML, XML documents, HWP3, archives and mail are valid and enabled. `ScanOneNote`, `ScanImage` and `ScanImageFuzzyHash` are omitted but default to `yes` in 1.5, so there is no present functional loss. Explicit settings would make intended coverage auditable across upgrades. |
| `:104` `Bytecode yes` | Correct and important. The official sample warns that disabling it loses many new detections. Keep `BytecodeSecurity TrustSigned` at its safe default and never enable unsigned bytecode for third-party feeds. |
| `:105` `HeuristicAlerts yes` | Correct if heuristic names remain non-conclusive evidence. |
| omitted `HeuristicScanPrecedence` | Correctly defaults to `no`. The official documentation specifically says to keep it disabled when `Heuristics.*` must be handled differently; otherwise a heuristic can stop the scan before a stronger result. |
| `:108` `AlertBrokenExecutables no` | Sensible. ClamAV documents false-positive risk; Sentinel already emits weak PE-malformation signals. |
| `:108` `AlertEncrypted no` | Too weak for coverage reporting. Opaque encrypted members can leave an `OK`. Enable `AlertEncryptedArchive yes` and `AlertEncryptedDoc yes`, but map the resulting heuristic to incomplete/unknown coverage and at most suspicious evidence. **RT-014**. |
| `:108` `AlertExceedsMax no` | Wrong for Sentinel’s stated coverage model. It hides `MaxFileSize`, `MaxScanSize`, `MaxFiles`, `MaxRecursion` and `MaxScanTime` exhaustion. ClamAV emits `Heuristics.Limits.Exceeded.*` when enabled. This must be coverage metadata, not malware. **RT-012**. [ClamAV limit alert history](https://blog.clamav.net/2021/11/clamav-01034-and-01041-patch-releases.html) |
| `:108` `AlertOLE2Macros no` | Leaves a useful document signal disabled. Enable only after the policy maps `Heuristics.OLE2.ContainsMacros` to weak/suspicious; macros alone are not malware. |
| `:109` `DetectPUA no` | Deliberately excludes ClamAV PUA databases. It is reasonable during baseline measurement, but later enabling it would add adware/riskware coverage. Every PUA match must remain notify-only unless corroborated. [ClamAV PUA documentation](https://docs.clamav.net/faq/faq-pua.html) |
| omitted `PhishingSignatures`/`PhishingScanURLs` | Both default to `yes`; they are active despite not appearing in the file. Explicit `yes` would improve auditability. |
| omitted `StructuredDataDetection` | Correctly remains off. It is a DLP detector for credit-card/SSN-like data, not malware protection, and would create irrelevant alerts. |
| missing database-age policy | Add a small `FailIfCvdOlderThan` threshold or equivalent Sentinel-side readiness check. This extends existing **RT-010**: an update failure must not leave an old database silently trusted. |
| `freshclam` `:113-121` | Shared directory, official mirror, scripted updates and bytecode download are correct. `TestDatabases` remains safely enabled by default. `ReceiveTimeout 0` disables its internal receive limit, but `update()` has an outer 1800-second subprocess timeout at `clamav.py:127-143`. `Checks` is irrelevant because Sentinel invokes one-shot updates rather than running freshclam as a daemon. |

### Quick clamd configuration changes

These should be a separate, small change group:

| Priority | Change | Policy requirement | Harmless proof |
|---:|---|---|---|
| 1 | `AlertExceedsMax yes` | `Heuristics.Limits.Exceeded.*` means `status=partial`, `verdict=unknown` absent other evidence; never quarantine. | A temporary archive containing harmless small members beyond a reduced test-only `MaxFiles`. |
| 2 | `AlertEncryptedArchive yes`; `AlertEncryptedDoc yes` | Opaque content is incomplete coverage; the encrypted flag is weak evidence only. | Fake clamd replies for both names, plus a harmless encrypted-container fixture if the test tooling can create one safely. |
| 3 | `AlertOLE2Macros yes` | Macro presence is suspicious/weak, not malicious. | Fake `Heuristics.OLE2.ContainsMacros` response; require notify-only. |
| 4 | Explicit `PhishingSignatures yes`, `PhishingScanURLs yes`, `ScanOneNote yes`, `ScanImage yes`, `ScanImageFuzzyHash yes` | No verdict change; makes intended defaults auditable. | Config-generation assertion. |
| 5 | Quote/escape all dynamic Windows paths | Startup failure must remain unavailable, never clean. | Temporary `SENTINEL_HOME` whose path contains spaces; parse/start against a harmless empty test database or parser-only check. |
| 6 | Database-age readiness limit | Stale database is unavailable/degraded coverage. | Inject an old fake database-version result; require no trusted-clean result. |
| 7 | Trial `DetectPUA yes` only after FP baseline | `PUA.*` remains suspicious/notify-only. | Fake PUA response plus a manifest of harmless utilities; no auto-quarantine. |

Keep `HeuristicScanPrecedence no`, `AlertBrokenExecutables no`, `StructuredDataDetection no`, and unsigned bytecode disabled.

## A3. What ClamAV `OK` proves in Sentinel

`Clamd._stream()` sends the stream and reads one textual reply (`clamav.py:195-225`). `_scan()` maps exactly `stream: OK` to `"clean"` (`clamav.py:328-344`). Scanner then stores that status without checking internal coverage (`scanner.py:117-144`).

An `OK` means only:

> The connected daemon reported no enabled signature or heuristic alert in the portions it actually processed, using its loaded engine/configuration/database.

It does **not** prove:

- the daemon processed every extracted member or byte;
- recursion, member count, total expanded size, normalization or scan-time limits were not reached;
- encrypted members were readable;
- the database was current;
- the daemon was Sentinel’s authentic process;
- unknown malware was behaviorally safe;
- later path-based engines inspected the same file generation.

### Result-interpretation findings

| ID | Finding |
|---|---|
| **RT-001** | `finding_for()` makes only `Heuristics.*` and `PUA.*` medium; every other name becomes critical (`clamav.py:228-233`). `Verdict.label` makes any critical finding malicious (`verdict.py:61-72`), and `act_on()` auto-quarantines malicious results (`protection.py:23-42`). This remains the destructive-action risk identified in round 4. |
| **RT-004** | Partial coverage can still leave the global label clean because label calculation uses findings only. Oversized ZIP handling can also clear `v.skipped` (`scanner.py:94-110`). Contract v1 is the correct fix. |
| **RT-005** | Files over 64 MiB are reopened for rules and ClamAV (`scanner.py:181-210`, `clamav.py:182-193`); Defender later scans the pathname. Size/mtime is weaker than binding every layer to one stable identity. |
| **RT-008/009/010** | Defender failure ambiguity, caching of incomplete/transient results, and failed-update retry suppression further weaken “clean.” These are already assigned in round 4 and should not be duplicated. |
| **RT-012** | ClamAV internal limit exhaustion is hidden by `AlertExceedsMax no`, yet `OK` becomes clean. |
| **RT-013** | If ClamAV is unavailable or errors (`clamav.py:332-344`) and no other engine finds anything, `Verdict.label` remains `clean`; `act_on()` then returns immediately. The UI may show an engine error, but the machine-readable top verdict is false-clean. |
| **RT-014** | Encrypted/uninspectable inner content is not represented as incomplete coverage. |
| **RT-015** | Generated Windows config paths are not quoted; the official Windows sample quotes paths containing spaces. Validate and fix before claiming arbitrary per-user data paths work. |
| Locked R3 | An unverified process on the loopback port can answer `OK`. Section 11 already locks how unverified detections and clean results are treated; implementation choice remains deferred to quarantine hardening. |

### Signature-name strength

The clamd reply exposes a name, not whether the match came from a full-file hash, generic body signature, logical rule, bytecode or third-party database. Official names generally follow `platform.category.family-id-revision`, but third-party conventions vary. [ClamAV signature naming](https://docs.clamav.net/manual/Signatures.html)

Apply the locked section 11 policy:

- Always weak: `Heuristics.*`, `PUA.*`, explicit denylisted names such as the observed `Win.Trojan.Suspect-34`.
- Strong-family candidates: `Exploit.*`, `CVE_*`, Virus, Worm, Ransomware, Backdoor, Rootkit, Bootkit, Trojan, Dropper, Downloader, Botnet, Infostealer, Spyware, Keylogger and test/EICAR names.
- Weak rules take precedence: `PUA.Win.Exploit.*` stays weak.
- Do not make `Generic`, `Gen` or `Agent` weak merely by token.
- Do not classify `Packed`/`Obfuscated` until FP measurement supports it.
- Unknown names follow the owner’s locked quarantine-default policy, but should record source/database provenance and a structured signature ID under Contract v1.

## A4. Additional ClamAV signature sources

| Source | Value | Licence/access/update constraints |
|---|---|---|
| Cisco Talos official CVD | Baseline signed `main`, `daily`, bytecode and supporting databases. | Keep the latest supported patch to retain database access and signature compatibility. Usually one or two database publications daily. [CVD FAQ](https://docs.clamav.net/faq/faq-cvd.html), [EOL policy](https://docs.clamav.net/faq/faq-eol.html) |
| SaneSecurity | Phishing, malicious attachments, macros, URLs and selected malware hashes; it publishes per-pack FP-risk guidance. | Free commercial use is permitted, but copying/redistribution or selling requires permission; public mirrors can rate-limit/block abuse. Updates several times daily and provides GPG signatures. [Legal terms](https://sanesecurity.org/legal/), [feeds and risk](https://sanesecurity.com/usage/signatures/), [updater guidance](https://sanesecurity.com/usage/linux-scripts/) |
| URLhaus | Near-real-time URLs embedded in mail/web content, not a general PE malware-signature replacement. The ClamAV feed contains active/recent distribution URLs. | Auth key required; community API is fair-use, while commercial/for-profit use may require the enhanced paid API. The ClamAV database is advertised as updated once per minute. [URLhaus API](https://urlhaus.abuse.ch/api) |
| SecuriteInfo | Large executable/hash/generic/YARA/phishing sets and hourly “zero-hour” feed. | Current malware/generic/zero-hour databases require a paid subscription; Basic is primarily validation/old content. Public mirroring is prohibited and only supported freshclam download methods should be used. Vendor detection claims are self-reported, not independent lab evidence. [FAQ and terms](https://www.securiteinfo.com/clamav-antivirus/faq-clamav-unofficial-signatures_en.shtml) |
| MalwarePatrol | ClamAV-compatible threat-data format; chiefly commercial threat-intelligence feeds. | Most enterprise feeds update hourly; licensing and download frequency are account/subscription controlled. [Integration formats](https://www.malwarepatrol.net/integrations-formats-threat-intelligence-feed-integration/), [feed update policy](https://www.malwarepatrol.net/tech-support/) |

Recommendation: do not auto-promote an entire third-party pack to conclusive evidence. Record `source`, database digest/version and exact signature ID; stage updates; load-test them; retain the previous version for rollback; and measure false positives before enabling auto-action.

---

# Part B — Commercial endpoint architectures

## B1. Bitdefender

### Documented facts

Pre-execution:

- Bitdefender Shield scans accessed files and email messages. [Real-time protection](https://www.bitdefender.com/consumer/support/answer/13450/)
- GravityZone **HyperDetect** adds pre-execution AI/ML heuristics for advanced, obfuscated, fileless, exploit, ransomware and PUA activity. [HyperDetect](https://www.bitdefender.com/business/support/en/77209-342938-hyperdetect.html)
- **Global Protective Network (GPN)** provides cloud connectivity/reputation and global threat intelligence. [GravityZone communication requirements](https://www.bitdefender.com/business/support/en/77212-376333-gravityzone-communication-ports.html), [GPN threat intelligence](https://techzone.bitdefender.com/en/gravityzone-platform/threat-intelligence.html)
- **Sandbox Analyzer** detonates suspicious files or scripts in a contained cloud environment and returns a pre-execution verdict. [Business Security Premium](https://www.bitdefender.com/en-us/business/products/gravityzone-premium-security)

On execution:

- Consumer **Advanced Threat Defense** and business **Advanced Threat Control** continuously monitor processes, score correlated suspicious behaviors and block after a threshold. [Advanced Threat Defense](https://www.bitdefender.com/consumer/support/answer/2024/), [Advanced Threat Control](https://www.bitdefender.com/business/support/en/77212-376309-advanced-threat-control.html)
- **Advanced Anti-Exploit** monitors commonly targeted applications and process-hijacking/memory-corruption behavior. [GravityZone overview](https://www.bitdefender.com/business/support/en/77209-79436-welcome-to-gravityzone.html)
- **Ransomware Mitigation** monitors activity, blocks the responsible process and uses protected backups to restore affected files. [Ransomware technical brief](https://www.bitdefender.com/content/dam/bitdefender/business/antiransomware/Bitdefender-Whitepaper-Antiransomware-Solution.pdf)

Web/email:

- Consumer **Online Threat Prevention** includes web, encrypted-web, fraud, phishing, network and email protection; Antispam is separate. [Protection-module list](https://www.bitdefender.com/consumer/support/answer/28557/)
- GravityZone also has traffic scanning, content control, network protection and optional Exchange/email products; exact availability varies by licence.

### OS dependencies: fact versus inference

Documented:

- Installation requires administrator rights for system-level components. [Installation requirements](https://www.bitdefender.com/consumer/support/answer/118763/)
- Current BEST release notes identify kernel-level API monitoring and a Network Protection driver. [BEST Windows release notes](https://www.bitdefender.com/business/support/en/77209-77540-windows-agent.html)
- Fileless Attack Protection integrates with Windows **AMSI** for scripts and dynamic buffers. [Bitdefender fileless protection](https://techzone.bitdefender.com/en/security-layers/protection/fileless-protection.html)

Inference:

- Reliable pre-open/on-access blocking normally needs a file-system minifilter or equivalent privileged component; Microsoft identifies anti-malware as a canonical minifilter use. Bitdefender’s public material reviewed here does not name its file minifilter. [Microsoft minifilter documentation](https://learn.microsoft.com/en-us/Windows-hardware/drivers/ifs/about-file-system-filter-drivers)
- A privileged service is needed to coordinate drivers, quarantine, policy and updates.
- Public sources reviewed here do not establish that Bitdefender uses ETW for these layers; do not state ETW as fact.

## B2. Malwarebytes

### Documented facts

Pre-execution/static:

- The **Katana** engine, announced in 2019, combined existing engines with dynamic zero-hour and behavior detection. This naming source is old; current product documentation emphasizes the protection layers rather than repeatedly naming Katana. [Katana announcement](https://www.malwarebytes.com/blog/malwarebytes-news/2019/11/announcing-malwarebytes-4-0-smarter-faster-and-lighter)
- Current Malwarebytes describes signatures, heuristics, behavior analysis and cloud telemetry working together. [Current architecture summary](https://www.malwarebytes.com/why-us/more-than-a-scanner)
- `MachineLearning/Anomalous.*` represents deviation from a legitimate-file training set and is intended for zero-day files. [Machine-learning detection](https://www.malwarebytes.com/blog/detections/machinelearning-anomalous-100)
- `Malware.Sandbox.*` detections come from emulation/sandbox techniques intended to recognize packed or protected unknown malware. [Emulation detection](https://www.malwarebytes.com/blog/detections/malware-sandbox)

On execution:

- Windows real-time layers are **Malware Protection**, **Exploit Protection** and **Ransomware Protection**. Malware Protection prevents programs launching; Exploit Protection guards selected applications; Ransomware Protection detects attempts to lock files. [Current real-time protection](https://help.malwarebytes.com/hc/en-us/articles/31589448817563-Turn-on-Real-Time-Protection-in-Malwarebytes-for-Windows-and-Mac)
- Older Malwarebytes architecture material describes application hardening, exploit mitigation, application-behavior monitoring, anomaly ML, payload analysis and anti-ransomware behavior scoring as cooperative layers. It is approximately nine years old, so use it conceptually rather than as a current component specification. [Multi-vector brief](https://staging-www-dynamic.malwarebytes.com/pdf/white-papers/Malwarebytes_Multi-Vector-Protection.pdf)
- **Ransomware Rollback** in the EDR product used a local change cache and activity monitoring to restore changes for up to 72 hours. That public description is from 2020 and should be treated as historical unless reconfirmed for a selected current licence. [Rollback description](https://www.malwarebytes.com/de/blog/news/2020/02/threat-spotlight-robbinhood-ransomware-takes-the-drivers-seat)
- Its remediation engine groups associated artifacts rather than merely deleting the originally detected file. [Remediation description](https://www.malwarebytes.com/blog/detections/ransom-lockbit)

Web/email:

- **Web Protection** blocks scams, phishing, ransomware sites and hostile network destinations. **Browser Guard** adds browser-level malicious-site, scam, PUP and download blocking. [Web Protection](https://help.malwarebytes.com/hc/en-us/articles/34604795815963-Turn-on-Web-Protection-in-Malwarebytes-for-Windows-and-Mac), [Browser Guard](https://www.malwarebytes.com/solutions/safe-browser)
- I found no current consumer documentation for an independent endpoint email-scanning layer comparable to Bitdefender’s email protection. Attachments are instead covered when stored/opened, and links by web/browser protection.

### OS dependencies: fact versus inference

Documented:

- Malwarebytes describes the Windows product as multiple long-running services above native drivers and a native detection engine. [Windows architecture discussion](https://www.malwarebytes.com/blog/inside-malwarebytes/2026/09/the-hidden-work-of-modernizing-malwarebytes)
- Installation requires administrative permission. [Installation permissions](https://help.malwarebytes.com/hc/en-us/articles/33787607470363-You-do-not-have-sufficient-permissions-to-install-Malwarebytes)

Inference:

- Its pre-launch file blocking, exploit monitoring and protected ransomware activity require privileged/native observation points unavailable to ordinary Python.
- Public material reviewed here does not identify its exact minifilter, WFP, ETW or AMSI implementation. Those should not be asserted as vendor facts.
- Robust rollback requires protected storage and attribution that an unprivileged watcher cannot guarantee.

---

# Part C — Ranked recommendations

## Larger features

| Rank | Recommendation | Gap and borrowed idea | Feasibility / FP / effort | Modules and plan | Harmless proof |
|---:|---|---|---|---|---|
| 1 | Implement Contract v1 before adding detection | Fixes RT-004, RT-012, RT-013 and RT-014. Borrow commercial separation of layer status, evidence and final action. | Fully feasible in Python. Low FP because incomplete becomes unknown, not malicious. **L** | `engine/contract.py`, `scanner.py`, `verdict.py`, `protection.py`; **C3c → Contract v1** | Fake clamd returns OK, limit, encrypted, unavailable, error and timeout. Only complete OK may become trusted-clean. |
| 2 | Versioned ClamAV evidence/name policy plus separate quarantine policy | Fixes RT-001. Borrow ATD/ATC and anti-ransomware scoring/action separation. | Feasible. Low–medium FP depending denylist maintenance. **M** | New `clamav_policy.py`, `quarantine_policy.py`, `clamav.py`, `protection.py`; **quarantine hardening** | Fake responses for strong, weak, PUA, heuristic, unknown and third-party names; verify locked decisions and reason codes. |
| 3 | Bind every layer to stable content identity; authenticate clamd per locked R3 | Fixes RT-005 and false clean from a substituted daemon/file generation. Borrow the commercial assumption that evidence comes from trusted sensors observing one object. | Partly feasible user-mode. File handles/identity are feasible; same-user hostile interference cannot be eliminated completely without a protected broker/service. **L** | `scanner.py`, `clamav.py`, Defender adapter; **C3f/Contract/quarantine hardening** | Synthetic A/B same-size content swap between injected stages; fake listener with wrong PID/image identity. |
| 4 | Finish the locked smart scan | Covers files never generating watcher events: startup entries, scheduled tasks and already-running images. Borrow commercial threat-scan scope rather than whole-disk-only scanning. | Feasible read-only without admin; inaccessible objects counted. FP depends existing engines, not enumeration. **L** | `scanjob.py`, `watcher.py`, platform helpers, pipeline UI; **smart scan** | Injected providers return harmless duplicate paths from watched dirs, Run keys, tasks and process images; require canonical dedupe and inaccessible counters. |
| 5 | Validate Authenticode with `WinVerifyTrust`; use signer as contextual evidence only | Improves unknown-PE triage where ClamAV has no cloud reputation. Borrow known-good reputation concepts from GPN/Katana. | Feasible in user mode. Low FP if a signature never suppresses conclusive malware and “unsigned” is informational. **M** | `filetype.py`, `scanner.py`, Contract evidence; **after Contract v1** | Injected verifier returns trusted, invalid, revoked, unavailable; a “trusted” signer must not override a test-only malicious rule. |
| 6 | Add an optional hash-reputation provider interface | Covers signatures’ publication delay; borrows cloud reputation without uploading file contents. | Technically feasible without admin, but needs network privacy, caching, rate limits and a provider licence. Medium FP if reputation is stale; use as evidence, not sole auto-action initially. **M** | New reputation provider, `scanner.py`, feeds/cache; **after quarantine hardening** | Fake offline/rate-limit/unknown/malicious/benign responses; unknown/offline must not become clean and benign must not override conclusive local evidence. |
| 7 | Staged third-party ClamAV feed manager | Improves known-threat and URL/document coverage while preserving supply-chain control. | Feasible. Medium FP and operational risk. **M** | `clamav.py`, `feeds.py`, status UI; **after Contract and FP baseline** | Test-only harmless signature database with checksum/signature validation; reject malformed/unsigned update and retain prior generation. |
| 8 | Notify-only anomaly telemetry | Partially covers the missing behavior layer: unusually rapid changes in protected user folders, new persistence plus a newly observed executable, or related high-risk events. Borrow ATD/Anti-Ransomware correlation. | Only weakly feasible. Watchdog cannot reliably attribute writes to a process or prevent them. High FP; never auto-quarantine. **L** | `watcher.py`, event correlation, `protection.py`; **after smart scan** | Harmless temporary-directory file burst and synthetic Run-entry change; bounded events, one warning, no quarantine. |
| 9 | Do not attempt Python anti-exploit, AMSI provider, minifilter prevention or rollback | These require privileged native components, signed providers/drivers, protected storage or reliable process/file attribution. | **Not feasible** within the locked no-driver/no-admin product. A user-mode approximation would create a misleading protection claim. | Product documentation/limitations; **after current plan only if scope changes** | Documentation test/UI assertion that Sentinel identifies itself as post-write supplemental protection. |

AMSI itself is a Windows interface for script/file/memory streams and URL reputation, integrated into PowerShell, WSH and Office VBA. Registering Sentinel as a reliable antimalware provider would require a native, signed, system-level integration rather than the current ordinary Python agent. [Microsoft AMSI documentation](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)

## Recommended order

1. C3x fixes already agreed.
2. Contract v1 with explicit coverage and trusted-clean semantics.
3. ClamAV name/evidence policy and quarantine hardening.
4. Stable identity and locked clamd authentication work.
5. Smart scan.
6. Authenticode/reputation enrichment.
7. Only then evaluate third-party feeds and notify-only behavior correlation.

This preserves the locked plan and avoids adding more signals while incomplete scans and engine failures can still be represented as clean.

---

# Sources

- [ClamAV signature formats](https://docs.clamav.net/manual/Signatures.html)
- [ClamAV YARA limitations](https://docs.clamav.net/manual/Signatures/YaraRules.html)
- [ClamAV scanning and endpoint-suite disclaimer](https://docs.clamav.net/manual/Usage/Scanning.html)
- [ClamAV Windows limitations](https://docs.clamav.net/faq/faq-win32.html)
- [ClamAV 1.5.4 Windows configuration sample](https://raw.githubusercontent.com/Cisco-Talos/clamav/clamav-1.5.4/win32/conf_examples/clamd.conf.sample)
- [ClamAV false-positive guidance](https://docs.clamav.net/faq/faq-scan-alerts.html)
- [ClamAV database update FAQ](https://docs.clamav.net/faq/faq-cvd.html)
- [AV-TEST’s obsolete 2015 ClamAV measurement](https://www.av-test.org/en/news/linux-16-security-packages-against-windows-and-linux-malware-put-to-the-test/)
- [AV-Comparatives March 2026 Windows test](https://av-comparatives.org/tests/malware-protection-test-march-2026/)
- [Bitdefender HyperDetect](https://www.bitdefender.com/business/support/en/77209-342938-hyperdetect.html)
- [Bitdefender Advanced Threat Defense](https://www.bitdefender.com/consumer/support/answer/2024/)
- [Bitdefender GravityZone/Sandbox/Ransomware architecture](https://www.bitdefender.com/en-us/business/products/gravityzone-premium-security)
- [Bitdefender AMSI-based fileless protection](https://techzone.bitdefender.com/en/security-layers/protection/fileless-protection.html)
- [Malwarebytes Katana announcement](https://www.malwarebytes.com/blog/malwarebytes-news/2019/11/announcing-malwarebytes-4-0-smarter-faster-and-lighter)
- [Malwarebytes current real-time layers](https://help.malwarebytes.com/hc/en-us/articles/31589448817563-Turn-on-Real-Time-Protection-in-Malwarebytes-for-Windows-and-Mac)
- [Malwarebytes emulation detections](https://www.malwarebytes.com/blog/detections/malware-sandbox)
- [Malwarebytes native drivers/services architecture](https://www.malwarebytes.com/blog/inside-malwarebytes/2026/09/the-hidden-work-of-modernizing-malwarebytes)
- [Microsoft file-system minifilters](https://learn.microsoft.com/en-us/Windows-hardware/drivers/ifs/about-file-system-filter-drivers)
- [Microsoft AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [SaneSecurity terms and signature catalogue](https://sanesecurity.org/legal/)
- [URLhaus community API and access terms](https://urlhaus.abuse.ch/api)
- [SecuriteInfo ClamAV feed terms](https://www.securiteinfo.com/clamav-antivirus/faq-clamav-unofficial-signatures_en.shtml)