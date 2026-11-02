# Codex literature review — round 7 (read-only, web search)

Prompt: `docs/handoff/PROMPT_CODEX_LITERATURE.md`, 2026-11-02. Claims and citations are Codex's and
have not been independently re-checked by Claude; treat result numbers as the papers' own.

## Codex answer (verbatim)

# Sentinel Guard literature review

## Executive conclusion

Given Sentinel’s locked architecture, the strongest near-term gains are:

1. Safe, non-executing analysis of scripts, documents, shortcuts, and containers.
2. A calibrated PE gradient-boosted model used as a `suspicious` signal with abstention—not as an automatic quarantine verdict.
3. Better browser identity and download-provenance analysis.
4. Notify-only ransomware burst detection.
5. Strict temporal and low-false-positive evaluation around every new detector.

Research does **not** support attempting user-mode substitutes for kernel telemetry, AMSI integration, process-attributed filesystem interception, rollback, active rootkit detection, or EDR-style credential-access monitoring.

I treated the locked decisions in `PROJECT_CONTEXT.md` as constraints and did not rerank the Contract v1, quarantine, ClamAV, stable-identity, or Authenticode groundwork already covered by `codex-research-r5.md`. `docs/handoff/codex-product-r6.md` was not present.

Applicability labels below mean:

- **Direct:** implementable with Sentinel’s present privileges and data.
- **Adaptable:** useful only as a conservative signal or simplified version.
- **Not feasible:** needs kernel, process, network, store-scale, or cloud prevalence visibility Sentinel does not have.

---

## 1. File infectors, classic viruses, and worms

File infectors append, prepend, or alter executable sections and entry points. Worms additionally propagate through network services, shares, removable media, or user-launched attachments. Sentinel can examine the resulting files, but cannot reliably observe network-wide propagation.

| Approach | Key research | Reported result and caveats | Sentinel applicability |
|---|---|---|---|
| Exact signatures plus YARA invariants | Kornblum, 2006, DFRWS, [context-triggered piecewise hashing](https://dfrws.org/sites/default/files/session-files/2006_USA_paper-identifying_almost_identical_files_using_context_triggered_piecewise_hashing.pdf); Raff et al., 2020, AISec, [AutoYara](https://arxiv.org/abs/2009.03779) | AutoYara reported rules below 0.1% FP in its experiments. Automatically learned rules still require family-quality inputs and independent clean testing. | **Direct:** keep signatures conclusive only when curated; generated or broad YARA matches remain `suspicious`. |
| Section and import similarity | Oliver, Cheng & Chen, 2013, [TLSH](https://documents.trendmicro.com/assets/wp/wp-locality-sensitive-hash.pdf); Li et al., 2015, USENIX CSET, [fuzzy-hash evaluation](https://www.usenix.org/conference/cset15/workshop-program/presentation/li) | Similarity hashes help cluster related files, but full-file hashes are sensitive to packing and layout changes and can conflate unrelated files. | **Adaptable:** hash normalized executable sections, imports, and resources; never treat similarity alone as malicious. |
| Static PE ML | Anderson & Roth, 2018, [EMBER](https://arxiv.org/abs/1804.04637); Yang et al., 2021, IEEE S&P Workshops, [BODMAS](https://conferences.computer.org/sp/pdfs/spw/2021/893400a078.pdf) | Gradient-boosted PE features perform strongly, but BODMAS shows degradation and fluctuating FPR on later time periods. | **Adaptable:** useful for previously unseen variants, with temporal validation, abstention, and no automatic quarantine. |
| Propagation/system-call correlation | Ellis et al., 2006, RAID, [worm behavior correlation](https://doi.org/10.1145/1103626.1103641) | Detected a small set of worm variants using runtime events; the corpus and Windows environment are now obsolete. | **Not feasible:** Sentinel lacks process and network-event attribution. |

## 2. Trojans, droppers, downloaders, and loaders

These commonly arrive as fake installers, cracked software, email attachments, archives, scripts, or browser downloads. They often unpack or fetch a later payload, create persistence, and blend with legitimate tools.

| Approach | Key research | Reported result and caveats | Sentinel applicability |
|---|---|---|---|
| Calibrated static PE features | Anderson & Roth, 2018, [EMBER](https://arxiv.org/abs/1804.04637); Harang & Rudd, 2020, [SOREL-20M](https://arxiv.org/abs/2012.07634); EMBER authors, 2025, KDD, [EMBER2024](https://arxiv.org/abs/2506.05074) | GBDTs are competitive with deeper byte models. EMBER2024 adds six formats, a temporal split, and initially missed challenge files. Training labels remain vendor-derived. | **Adaptable:** add a small feature extractor and GBDT; output `suspicious` or abstain. |
| Raw-byte CNN | Raff et al., 2018, AAAI Workshop, [MalConv](https://cdn.aaai.org/ocs/ws/ws0432/16422-75958-1-PB.pdf) | Reported 95.8–98.5% AUC on its test groups, but EMBER’s feature-based baseline outperformed it. AUC does not establish safe low-FPR operation. | **Low priority/adaptable:** heavier and less explainable than GBDT for a Python desktop agent. |
| Packing-aware caution | Aghakhani et al., 2020, NDSS, [When Malware Is Packin’ Heat](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24310-paper.pdf) | Static classifiers did not generalize reliably to unseen packers; packer identity can become a spurious shortcut. | **Direct:** surface packing as uncertainty; do not label a file malicious merely for being packed. |
| Document/archive structural features | Rudd et al., 2018, IEEE HST, [MEADE](https://arxiv.org/abs/1804.08162) | Reported AUC above 0.99 on millions of Office and ZIP files, but used private labels and did not establish very-low-FPR deployment behavior. | **Adaptable:** safe metadata, nesting, macro, relationship, filename, and MIME/magic features. |
| Dynamic unpacking/API behavior | Common sandbox literature | Strong against staged loaders, but requires executing an untrusted file and observing process behavior. | **Not feasible:** forbidden by Sentinel’s safety model. |

## 3. Ransomware

Ransomware generally arrives as a trojan or script, then rapidly rewrites, renames, or deletes many user files. Some variants also steal data. A watchdog can observe path changes after they occur, but without a minifilter it cannot synchronously interpose, reliably identify the responsible process, or roll back writes.

| Approach | Key research | Reported result and caveats | Sentinel applicability |
|---|---|---|---|
| Filesystem behavior and decoys | Kharraz et al., 2016, USENIX Security, [UNVEIL](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/kharaz) | Tested 148,223 samples and reported 96.3% true positives with no observed FPs. It used sandbox instrumentation and lacked perfect ground truth. | **Adaptable:** rolling write/rename/delete bursts and Sentinel-owned decoys; notify only initially. |
| Content-change indicators | Scaife et al., 2016, ICDCS, [CryptoDrop](https://www.cise.ufl.edu/~butler/pubs/icdcs16.pdf) | Detected all 492 tested samples; median loss was about 10 files. Results reflect 2016 families and process-attributed interception. | **Adaptable:** bounded entropy/magic changes and extension fan-out, but detection will be later and less attributable. |
| Transparent detection and recovery | Continella et al., 2016, ACSAC, [ShieldFS](https://doi.org/10.1145/2991079.2991110); Kharraz & Kirda, 2017, RAID, [Redemption](https://theseclab.org/publications/raid2017redemption.pdf) | Demonstrated early detection and rollback through filesystem/process interception. | **Not feasible:** needs kernel or equivalent per-process I/O control. |
| Simple entropy threshold | Broader ransomware literature | Encryption often raises entropy, but compressed media, archives, databases, and legitimate encrypted files already have high entropy. | **Direct only as corroboration:** use entropy *change* plus burst/context; never entropy alone. |

## 4. Infostealers and credential theft

Infostealers are often delivered through malvertising, fake updates, cracked software, phishing, or staged loaders. They target browser profiles, cookies, session tokens, password stores, wallets, and system context before exfiltration.

| Approach | Key research | Reported result and caveats | Sentinel applicability |
|---|---|---|---|
| Detect the delivery artifact | Microsoft, 2025, [Digital Defense Report](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/bade/documents/products-and-services/en-us/security/Microsoft-Digital-Defense-Report-2025-v5-21Nov25.pdf) | Identifies stealers as a frequent initial payload distributed through deceptive downloads and social engineering. Vendor telemetry is broad but not independently reproducible. | **Direct:** URL/feed, attachment, script, PE, signer, and download-provenance layers are Sentinel’s best interception point. |
| Browser-session artifact research | 2026 empirical study, [large-scale infostealer-log analysis](https://www.sciencedirect.com/science/article/pii/S0167404826003524) | Studies credentials, browser sessions, keys, and certificates across a large privacy-preserving artifact corpus. The victim-log domain creates sampling and ethical limitations. | **Indirect:** informs what is at risk; Sentinel should not collect or inspect actual credentials. |
| Browser extension capability/risk | Fass et al., 2021, [DoubleX](https://publications.cispa.saarland/3464/1/fass2021doublex.pdf); Patnaik et al., 2024, The Web Conference, [password-field access](https://doi.org/10.1145/3589334.3645683) | Broad content access exposes sensitive fields; static analysis is neither sound nor complete. Permission alone does not prove maliciousness. | **Adaptable:** notify on risky permission changes, removed extensions, and anomalous provenance—not on permissions alone. |
| LSASS/browser database access behavior | Microsoft Research, [credential-theft access behavior](https://www.microsoft.com/en-us/research/publication/effective-detection-of-credential-thefts-from-windows-memory-learning-access-behaviours-to-local-security-authority-subsystem-service/) | Behavioral access models require memory/process telemetry. | **Not feasible:** no kernel/EDR sensor and no reliable attribution of sensitive-file reads. |

## 5. Fileless, script-based, and living-off-the-land abuse

PowerShell, WSH, LNK, HTA, macro documents, OneNote files, archives, and disk images often act as launch or staging layers. Payloads may live mostly in memory or invoke trusted Windows binaries.

| Approach | Key research | Reported result and caveats | Sentinel applicability |
|---|---|---|---|
| Static deobfuscation and semantics | Li et al., 2019, ACM CCS, [PowerShell deobfuscation](https://ics.uci.edu/~alfchen/pubs/zhenyuan_ccs19.pdf) | Reported 92.3% TPR with zero observed FP on its evaluated sets; similarity improved greatly after deobfuscation. The data is older and its partial execution techniques should not be copied into Sentinel. | **Adaptable:** non-executing tokenization, string folding, Base64 metadata, AST-like normalization, and suspicious API combinations. |
| AMSI-stream ML | Hendler, Kels & Rubin, 2019, [AMSI contextual embeddings](https://arxiv.org/abs/1905.09538) | Reported 89.4% TPR at at most 0.1% FPR on 116,976 deduplicated AMSI instances. It benefits from runtime-decoded content. | **Not feasible as described:** Sentinel is not an AMSI provider; use only file-level lessons. |
| LOTL prevalence analysis | Barr-Smith et al., 2021, IEEE S&P, [Survivalism](https://ieeexplore.ieee.org/abstract/document/9519480) | Across 31.8M samples, LOTL appeared substantially more often in advanced campaigns and exposed detection gaps. | **Adaptable:** treat trusted interpreter references as context, never as malicious by themselves. |
| Safe structural parsing | Rudd et al., 2018, [MEADE](https://arxiv.org/abs/1804.08162); Cisco Talos, 2023, [delivery-format observations](https://storage.ghost.io/c/af/a0/afa04ee3-414f-4481-8d23-7e7c146f192e/content/files/2023/12/2023_Talos_YiR.pdf) | Documents and archives expose useful structural features; campaign reports show frequent format shifts. Private labels and campaign bias limit generalization. | **Direct:** parse relationships, embedded names, macro presence, shortcut targets, archive nesting, and MIME/magic mismatch without opening content. |
| Runtime command-line/process trees | EDR/AMSI research | Most effective once a trusted interpreter has launched. | **Not feasible reliably:** absent ETW/AMSI/kernel process telemetry. |

## 6. Remote-access trojans and botnets

RATs usually arrive as loaders or trojans, then establish persistence and periodic command-and-control traffic. Bots may use hard-coded infrastructure, compromised services, or algorithmically generated domains.

| Approach | Key research | Reported result and caveats | Sentinel applicability |
|---|---|---|---|
| Static signatures, capabilities, and PE ML | [EMBER](https://arxiv.org/abs/1804.04637), [SOREL-20M](https://arxiv.org/abs/2012.07634), [AutoYara](https://arxiv.org/abs/2009.03779) | Useful before execution; family signatures age and static features are weakened by packing. | **Direct/adaptable:** scan executable and script artifacts; capability descriptions are explanatory, not verdicts. |
| Multi-stage network correlation | Gu et al., 2007, USENIX Security, [BotHunter](https://www.usenix.org/conference/16th-usenix-security-symposium/bothunter-detecting-malware-infection-through-ids-driven) | Correlated exploit, download, command-and-control, and propagation stages. Foundational but old and dependent on network monitoring. | **Not feasible:** Sentinel lacks host-wide DNS and flow visibility. |
| DGA detection | Schüppen et al., 2018, USENIX Security, [FANCI](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-schuppen.pdf); NIST, 2022, [AGD evaluation](https://www.nist.gov/publications/machine-learning-based-algorithmically-generated-domain-detection) | High performance is possible on known evaluation families, but family leakage and unrealistic priors can inflate accuracy. | **Adaptable:** lexical DGA score only when corroborated by reputation, download, login, or exact-domain evidence. |
| Known C2 blocklists | Operational threat intelligence | Effective for known campaigns but short-lived and vulnerable to domain churn. | **Direct:** exact-domain/IP metadata can be a strong feed signal with expiry and provenance. |

## 7. Cryptominers and cryptojacking

Native miners generally arrive as trojans or bundled PUA and consume CPU/GPU after launch. Browser cryptojacking uses JavaScript or WebAssembly, worker threads, and remote mining infrastructure.

| Approach | Key research | Reported result and caveats | Sentinel applicability |
|---|---|---|---|
| Static code and infrastructure characteristics | Kharraz et al., 2018, ACM CCS, [MineSweeper](https://sites.cs.ucsb.edu/~chris/research/doc/ccs18_minesweeper.pdf) | Identified 20 campaigns and showed that blacklists or CPU use alone were insufficient. | **Adaptable:** static JS/WASM signatures and expiring infrastructure feeds. |
| Browser runtime behavior | Konoth et al., 2019, [Outguard](https://theseclab.org/publications/cryptojacking.pdf) | Reported 97.9% TPR and 1.1% FPR across thousands of sites. Required instrumented execution. | **Not feasible in MV3:** no safe equivalent to its deep runtime instrumentation. |
| CPU-throttling/trace ML | Petrov et al., 2020, [CoinPolice](https://research.google/pubs/coinpolice-detecting-hidden-cryptojacking-attacks-with-neural-networks/) | Reported 97.87% detection and 0.74% FP. It used browser instrumentation and active measurement. | **Not feasible directly:** CPU use alone would create too many false positives. |
| Native-file detection | Static PE signatures/ML | Detects known miners and some bundled installers before launch. | **Direct:** scan miner PE files and installers; keep “high CPU” out of the verdict path. |

## 8. Adware, PUA, and malicious browser extensions

PUA often arrives through pay-per-install bundles, misleading consent flows, or fake utilities. Malicious extensions may inject ads, modify searches, steal page data, or receive a malicious update. The PUA boundary is partly about informed consent, not just code behavior.

| Approach | Key research | Reported result and caveats | Sentinel applicability |
|---|---|---|---|
| Separate PUA classification | Kotzias et al., 2016, USENIX Security, [PUP ecosystem](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/kotzias) | Shows a large pay-per-install ecosystem and ambiguous relationships between signed installers, affiliates, and unwanted behavior. | **Direct:** create a separate PUA outcome; default to notify, not quarantine. |
| Extension reputation and dynamic review | Jagpal et al., 2015, USENIX Security, [WebEval](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-jagpal.pdf) | Reported 96.5% measured detection and identified 9,523 malicious extensions, using Google-scale dynamic analysis and human review. Old/private features limit reproduction. | **Adaptable:** use store status, extension identity, version, permissions, and removal metadata; no store-scale dynamic execution. |
| Ad-injection measurement | Thomas et al., 2015, WWW, [Ad Injection at Scale](https://research.google/pubs/ad-injection-at-scale-assessing-deceptive-advertisement-modifications/) | Associated ad injection with tens of thousands of extensions and Windows binaries; prevalence was substantial in the measured population. | **Adaptable:** correlate unwanted page modification with installed extension changes, but avoid automatic blame. |
| Cross-store persistence | NDSS, [malicious extensions across stores](https://www.ndss-symposium.org/ndss-paper/auto-draft-713/) | Found malicious extensions that survived longer in one store after removal from another. | **Direct if metadata is available:** cross-store removal is stronger evidence than broad permissions. |
| Whole-store taint/dynamic analysis | Xie et al., 2024, USENIX Security, [Arcanum](https://www.usenix.org/conference/usenixsecurity24/presentation/xie-qinge) | Demonstrated deeper privacy analysis across functional extensions and sensitive sites. | **Not feasible:** too heavy and requires executing untrusted extension behavior. |

## 9. Phishing and malicious web pages

Phishing reaches users through email, search advertising, social media, messages, QR codes, redirects, and compromised sites. Pages imitate brands, request credentials, or direct users to malicious downloads.

| Approach | Key research | Reported result and caveats | Sentinel applicability |
|---|---|---|---|
| Exact URL/domain feeds | Operational blocklists | High precision for known pages, but coverage decays quickly and live URLs are unsafe evaluation inputs. | **Direct:** exact match with provenance, expiry, and offline fixtures; never visit dataset URLs during testing. |
| Lexical URL ML | Le et al., 2018, [URLNet](https://arxiv.org/abs/1802.03162) | Used millions of temporally ordered URLs and improved over prior lexical models. Treating URLs with no VirusTotal detections as benign introduces label noise. | **Adaptable:** local lightweight model or engineered score; never block on lexical score alone. |
| Visual brand matching | Lin et al., 2021, USENIX Security, [Phishpedia](https://www.usenix.org/conference/usenixsecurity21/presentation/lin); Abdelnabi et al., 2020, CCS, [VisualPhishNet](https://s-abdelnabi.github.io/VisualPhishNet/) | Phishpedia found 1,704 new pages in a 30-day deployment, many not yet on VirusTotal. Brand-reference coverage and cross-dataset variation remain limitations. | **Adaptable:** logo/form/domain mismatch; a full vision stack is probably too heavy for MV3. |
| Multimodal page intention | Liu et al., 2022, USENIX Security, [PhishIntention](https://www.usenix.org/conference/usenixsecurity22/presentation/liu-ruofan) | On 50,000 pages and a field study, reported similar detections with 86.5% fewer FPs than its best baseline. It relies on heavier browser and visual analysis. | **Adaptable:** DOM login intent, external form action, page title/logo, and registrable-domain mismatch. |
| Correct domain identity | Public Suffix List and IDNA processing | Hand-coded suffix rules misidentify registrable domains and create both misses and FPs. | **Direct:** replace the current suffix approximation with an offline PSL and strict IDNA normalization. |

## 10. Rootkits and bootkits

Kernel rootkits alter or hide operating-system state. Bootkits execute before or underneath the normal OS trust boundary. A user-mode scanner may detect a known installer before activation, but cannot establish that an already compromised kernel is telling the truth.

| Approach | Key research | Reported result and caveats | Sentinel applicability |
|---|---|---|---|
| Static detection of installers/drivers | Signature/YARA/hash research | Known dropper or driver files may be detected before installation. Signed malicious drivers remain possible. | **Direct but narrow:** detect known artifacts; do not claim active-rootkit detection. |
| In-OS integrity checking | Petroni et al., 2004, USENIX Security, [Copilot](https://www.usenix.org/legacy/events/sec04/tech/full_papers/petroni/petroni_html/) | Demonstrated why independent observation is required; foundational and old. | **Not feasible:** user-mode observations depend on the possibly compromised kernel. |
| Below-OS detection | King et al., 2006, IEEE S&P, [SubVirt](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/subvirt.pdf) | Shows how malware beneath the OS defeats in-guest assumptions. Foundational, not representative of all modern bootkits. | **Not feasible:** no external hypervisor, firmware, or hardware monitor. |
| Secure boot/offline remediation | Microsoft, [Windows boot security and ELAM](https://learn.microsoft.com/en-gb/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process) | Relies on platform trust, signed early-launch components, and offline recovery. | **Referral only:** recommend Secure Boot, Defender Offline, and professional remediation. |

---

## Cross-cutting technique assessment

### Fuzzy hashing and YARA

Full-file ssdeep or TLSH should be treated as a triage aid, not a detector. Section-level and normalized hashes are generally more meaningful, but still need compatible file type, size, and structure constraints. `imphash` is useful for grouping related PE import patterns, yet common library templates and packers make it too coarse for a malicious verdict.

Research evaluations of similarity hashing have produced contradictory rankings because “similarity” depends on the task and corpus; see Pagani et al., 2018, [Beyond Precision and Recall](https://www.researchgate.net/publication/323785081_Beyond_Precision_and_Recall_Understanding_Uses_and_Misuses_of_Similarity_Hashes_in_Binary_Analysis).

For YARA, every rule should have:

- A stated family/campaign scope and source.
- A minimum engine version and expiry/review date.
- Positive structural conditions, not only a short string.
- A held-out clean-software FP result.
- A weak or strong policy class consistent with Contract v1.
- No automatic promotion merely because several correlated weak rules matched.

### Authenticode, reputation, and prevalence

A valid signature is useful negative/contextual evidence, not an allow verdict. Kim, Kwon & Dumitraș, 2017, [Certified Malware](https://users.umiacs.umd.edu/~tdumitra/papers/CCS-2017.pdf), and Kotzias et al., 2015, [Certified PUP](https://software.imdea.org/~juanca/papers/malsign_ccs15.pdf), document stolen certificates, malicious signed files, PUA signing, and revocation shortcomings.

Google’s CAMP study—Rajab et al., 2013, NDSS, [Content-Agnostic Malware Protection](https://securitysteve.net/wp-content/uploads/2017/07/content-agnostic-malware-protection.pdf)—reported high production effectiveness by combining download origin, prevalence, reputation, signature, and local allowlisting. Sentinel cannot reproduce Google-scale prevalence, but it can preserve final URL, referrer, MIME/magic, Mark-of-the-Web, signer, and hash-reputation context.

---

## Evaluation methodology Sentinel should adopt

| Requirement | Recommended Sentinel practice |
|---|---|
| Temporal realism | Train on earlier timestamps and test on later periods. Never randomly split near-duplicate variants across train and test. [TESSERACT](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury) and [Transcend](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/jordaney) show how temporal and spatial bias exaggerate performance. |
| Family/source separation | Deduplicate exact hashes; where metadata permits, group near-duplicates and malware families before splitting. Report when family labels are unavailable. |
| Low-FPR reporting | Report TPR at fixed 0.1% and 0.01% FPR, not just accuracy, F1, or ROC-AUC. Include confidence intervals because a few clean errors dominate at these operating points. |
| Realistic clean corpus | Test Windows components, signed and unsigned applications, installers, developer tools, game/mod utilities, portable software, archives, scripts, and locally installed applications. Report FP per file and per scanned device, not only percentages. |
| Abstention | Permit `unknown`/`suspicious` when confidence or coverage is inadequate. A failed parser, truncated scan, packed file, or unsupported format is never `clean`. |
| Freeze before testing | Freeze model, rules, feeds, thresholds, and feature versions before evaluating the test period. |
| Separate evaluations | Report static-component detection separately from whole-product protection. Sentinel cannot fairly claim equivalence to a lab test that executes malware and observes post-launch blocking. |
| Lab alignment | Publish a test plan and product settings following [AMTSO’s principles](https://www.amtso.org/standards/). Track protection and false alarms separately as in [AV-Comparatives](https://av-comparatives.org/tests/malware-protection-test-march-2026/) and [AV-TEST usability](https://www.av-test.org/en/about-the-institute/test-procedures/test-modules-under-windows-usability/). |

---

# Top 10 improvements

The ranking weighs likely additional threat coverage, implementation effort, and FP risk. Existing r5 prerequisites—Contract v1, safe quarantine, stable identity, ClamAV integration, and baseline FP measurement—remain mandatory.

| Rank | Improvement | What and where | Phase | Data and licence | Harmless validation |
|---:|---|---|---|---|---|
| 1 | **Safe attachment and script analyzer** — high gain, medium effort, low–medium FP | Add bounded structural parsers for LNK, HTA, JS/VBS/WSF/PS1, Office/OLE, OneNote metadata, ZIP, ISO/IMG manifests, and nested MIME/magic mismatches. Integrate through `engine/filetype.py`, `engine/scanner.py`, and new script/document analyzer modules. No execution or emulation. | **Phase 6**, after Contract v1 regression | `oletools` fixtures/code are BSD; use project-owned synthetic fixtures and locally owned benign documents. MEADE data is not public enough to depend on. | Generate malformed and nested harmless fixtures, inert macro text, shortcut targets pointing to benign executables, and archive bombs represented only by metadata. Verify bounded time/memory and that structural indicators alone do not produce `malicious`. |
| 2 | **Calibrated PE GBDT with abstention** — high gain, medium effort, medium FP | Implement EMBER-compatible, bounded PE features and a small LightGBM model in a new `engine/static_ml.py`. Record model/feature version in Contract v1. Use only as `suspicious` unless corroborated by a conclusive source. | **Phase 6**, after Phase 4 and first FP baseline | EMBER 2017/2018 feature data: MIT data; original code AGPL-3. EMBER2024 repo code is Apache-2.0; verify its dataset card before redistribution. | Forward-chain feature-only EMBER/BODMAS periods; then measure 0.1% and 0.01% FPR on installed clean software and harmless project-built PE variants. No binaries from malware datasets. |
| 3 | **Correct browser identity and lightweight page-intent checks** — high gain, medium effort, low FP | Replace hand-written eTLD rules with an offline PSL and strict IDNA handling. Combine registrable-domain identity with login-form action, password field, title/logo text, and brand-domain mismatch in `url_heuristics.js`, `page_guard.js`, `background.js`, and `urlintel.py`. | **Phase 5 extension**, refined in **Phase 6** | PSL is MPL-2.0. Use project-created pages and clearly licensed brand reference metadata; Phishpedia/VisualPhish assets should be research-only until redistribution rights are confirmed. | Local `*.test` fixtures: homoglyph-like text, subdomain deception, shared-hosting paths, cross-domain forms, legitimate SSO, and multilingual pages. No navigation to live phishing URLs. |
| 4 | **Download provenance evidence** — high gain, medium effort, low FP | Pass final URL, redirect/referrer context, declared MIME, magic type, Mark-of-the-Web zone, filename changes, signer state, and optional hash reputation through the extension/native-host/scanner contract. Never let a signature override a conclusive blocklist/signature result. | **Phase 5–6** | User-owned local metadata; optional providers must permit hash-only queries and local caching. | Synthetic native messages and local HTTP fixtures, including renamed installers, MIME mismatches, signed benign applications, and missing metadata. |
| 5 | **Notify-only ransomware burst detector** — medium–high gain, medium effort, medium FP | Add per-directory rolling counts for rewrite/rename/delete bursts, extension fan-out, bounded before/after entropy samples, and Sentinel-owned decoys in `watcher.py`/protection state. Do not claim process attribution or rollback. | **Phase 6** | No external data required; synthetic corpus can use the project’s own licence. | In a temporary test tree, perform harmless mass renames, reversible byte transformations, backup restores, builds, archive extraction, database writes, and photo imports. Measure time-to-alert, files changed, and false alerts. |
| 6 | **Normalized similarity metadata** — medium gain, low–medium effort, low FP if weak | Add code-section TLSH, normalized section hashes, import-set/imphash, and resource hashes in a similarity module and database. Feed only curated fingerprints/prototypes, never raw samples. | **Phase 6** | TLSH implementation is Apache-2.0; external fingerprint feeds require explicit redistribution and provenance terms. | Compile several harmless versions of the same local program with resource/compiler changes; compare against unrelated clean programs. Similarity must remain `suspicious`. |
| 7 | **Installed-extension hygiene audit** — medium gain, medium effort, low–medium FP | Inventory extension ID, version, source/store, externally managed status, permission changes, and removal/reputation state. First verify Helium’s management API and local manifest accessibility. Notify on changes; do not classify broad permissions alone. | **Phase 6** | Store metadata terms vary. Store only identity/version/reputation metadata, not extension packages. | Synthetic extension manifests representing benign high-permission tools, permission upgrades, removed IDs, sideloaded development extensions, and cross-store status differences. |
| 8 | **Explicit PUA/adware evidence channel** — medium gain, low effort, lower user-harm risk | Add `pua`/`potentially_unwanted` policy distinct from malicious. Map ClamAV PUA and browser-modification evidence to notify/choice by default. Update contract, UI, and `clamav_policy.py`. | **Phase 6**, after FP baseline | Existing ClamAV databases/tools are GPL-family licensed; confirm redistribution terms for any additional feed. Local benign utilities supply the FP corpus. | Test harmless admin utilities, bundlers, unsigned portable apps, search-setting fixtures, and synthetic ad insertion. Verify no automatic quarantine from PUA evidence. |
| 9 | **Corroborated DGA/URL lexical signal** — modest gain, low effort, medium FP if isolated | Add a small lexical domain score to `url_heuristics.js`/`urlintel.py`, but permit blocking only when combined with exact reputation, suspicious page intent, or malicious-download evidence. | **Phase 6** | UMUDGA is CC BY and contains generated domain names, not binaries. Use a licensed benign-domain list or locally captured clean domains for FPs. | Temporal/family holdout over feature-only domains; set a very-low-FPR threshold and test CDN, telemetry, gaming, and randomly generated legitimate hostnames. |
| 10 | **Temporal drift and FP release gate** — indirect but essential gain, medium effort, very low FP | Version models/features/rules, generate forward-chaining reports, track alert volume and abstentions, and reject updates that exceed a fixed clean-corpus budget. Extend `reports/`, `feeds.py`, and Contract v1 metadata. | **Phase 7** | EMBER/BODMAS feature-only subsets plus periodic snapshots of locally installed clean software. Do not redistribute local binaries. | Simulate monthly releases, freeze each candidate, evaluate on the next period, and automatically fail promotion if coverage or FP limits regress. |

---

# Safely usable datasets and tools

“Live binaries” means executable malware or malware-derived executable content. Sentinel should not download those portions even if a dataset labels them “disarmed.”

| Dataset/tool | Licence/terms | Live malware binaries? | Safe Sentinel use |
|---|---|---:|---|
| [EMBER 2017/2018](https://github.com/elastic/ember) | Feature dataset MIT; original code AGPL-3.0 | **No**, if using feature-vector release only | Train/evaluate PE feature models without obtaining executables. |
| [EMBER2024](https://github.com/futurecomputing4ai/ember2024) | Repository code Apache-2.0; confirm dataset-card terms before redistribution | **No** for feature/label release | Preferred modern temporal benchmark; use features only. |
| [SOREL-20M](https://registry.opendata.aws/sorel-20m/) | Code Apache-2.0; data governed by separate terms of use | **YES — dataset storage includes malware-derived/disarmed binaries** | Use only feature and metadata tables. Do not access or download binary objects. |
| [BODMAS](https://github.com/whyisyoung/BODMAS) | Repository BSD-2-Clause; confirm that the data grant covers intended redistribution | **YES — binary archive exists** | Use only the feature CSV and labels. Do not download the PE archive. |
| [UMUDGA](https://webs.um.es/mattia.zago/assets/papers/UMUDGA-DiB.pdf) | CC BY | No; domain strings/features | DGA research, with family/time separation. |
| [PhishTank](https://phishtank.org/terms.php) | Restrictive service/API terms; commercial and noncommercial conditions differ | No binaries, but **URLs may still be dangerous/live** | Ingest URL strings and historical metadata offline. Never navigate to them. |
| [Phishpedia](https://github.com/lindsey98/Phishpedia) | Research repository; confirm dataset and brand-asset rights separately | No malware binaries; HTML/URLs may be dangerous | Offline screenshots, annotations, and brand-reference methodology only. Strip active content and never load remote resources. |
| [VisualPhishNet](https://s-abdelnabi.github.io/VisualPhishNet/) | Academic access; redistribution licence is not clearly broad | No binaries; URLs/pages may be unsafe | Research evaluation only until rights are clarified. |
| Local installed-software corpus | User-owned installations; do not redistribute binaries | No intentional malware | Primary FP corpus: Windows files, installed apps, developer tools, installers, portable utilities, and unsigned local builds. |
| Synthetic Sentinel corpus | Project-controlled licence | No | Harmless PE builds, inert script syntax, malformed containers, local phishing pages, and reversible filesystem activity. |
| [YARA-X](https://github.com/VirusTotal/yara-x) | BSD-3-Clause | No samples included by the engine | Existing rule execution with time/size limits and rule provenance. |
| [oletools](https://pypi.org/project/oletools/) | BSD | No samples required | Non-executing Office/OLE structure and macro-text extraction. |
| [capa](https://github.com/mandiant/capa) | Apache-2.0 | Tool itself: no | Optional explanation-only capabilities, consistent with the locked decision; not a verdict source. |
| [TLSH](https://github.com/trendmicro/tlsh) | Apache-2.0 | No | Similarity metadata only, preferably per normalized section. |

Never use public malware exchanges, sample-sharing sites, or live phishing pages for Sentinel’s development or validation. Hashes, feature vectors, metadata, screenshots with active content removed, and synthetic files are sufficient for the proposed experiments.

---

# Open questions and weak evidence

1. **What FP budget is acceptable?** Research commonly reports 0.1% FPR, but scanning hundreds of thousands of files makes even that operationally noisy. Sentinel needs a device-level alert budget, not only a per-file percentage.

2. **Will an EMBER-compatible model transfer to home-PC software?** Public datasets contain vendor and VirusTotal sampling biases. Results must be recalibrated on Vietnamese consumer software, game launchers, unsigned utilities, and developer tools.

3. **How much ransomware lead time remains with watchdog?** Published successes mostly use synchronous interception and process attribution. Sentinel’s post-event watcher may detect a burst only after significant damage, especially under event coalescing or queue overflow.

4. **Can Helium expose reliable extension-management metadata?** Chrome/Edge research assumes store and management APIs that Helium may implement differently. Feasibility must be checked before committing to extension audits.

5. **Are public script/document corpora current enough?** Strong PowerShell and Office studies rely on private or older telemetry. There is no clearly licensed, modern, feature-only corpus covering current LNK, OneNote, HTA, WSH, and nested-container campaigns.

6. **How should prevalence be obtained without harming privacy?** CAMP-like reputation is powerful, but local installation prevalence and cloud hash lookups raise privacy, availability, and licensing questions. No file contents or user paths should leave the machine.

7. **Does lightweight brand matching improve on the current extension at acceptable cost?** Research vision systems are heavier than MV3 permits and depend on curated brand references. A DOM/text/logo-lite approach needs independent FP measurement on SSO, banks, payment processors, and shared hosting.

8. **How should PUA consent be represented?** Research confirms that PUA classification is contextual. Sentinel needs user-facing distinctions among malicious, deceptive, bundled, admin/riskware, and merely uncommon software.

9. **Can similarity prototypes be distributed legally and safely?** Hashes and fingerprints are safer than samples, but feed providers may restrict redistribution, derived data, or commercial use.

10. **How should model uncertainty combine with the locked conclusive-source policy?** There is evidence for uncertainty-aware operation at extreme low FPR—e.g. [Leveraging Uncertainty for Malware Detection](https://arxiv.org/abs/2108.04081)—but limited evidence for calibrating heterogeneous local AV, feed, document, and browser signals together. Conservative abstention is better supported than confidence-score voting.

---

## Sources

- Static ML and drift: [EMBER](https://arxiv.org/abs/1804.04637), [MalConv](https://cdn.aaai.org/ocs/ws/ws0432/16422-75958-1-PB.pdf), [SOREL-20M](https://arxiv.org/abs/2012.07634), [EMBER2024](https://arxiv.org/abs/2506.05074), [BODMAS](https://conferences.computer.org/sp/pdfs/spw/2021/893400a078.pdf), [TESSERACT](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury), [Transcend](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/jordaney), [packing study](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24310-paper.pdf).
- Signatures and similarity: [ssdeep](https://dfrws.org/sites/default/files/session-files/2006_USA_paper-identifying_almost_identical_files_using_context_triggered_piecewise_hashing.pdf), [TLSH](https://documents.trendmicro.com/assets/wp/wp-locality-sensitive-hash.pdf), [fuzzy-hash evaluation](https://www.usenix.org/conference/cset15/workshop-program/presentation/li), [AutoYara](https://arxiv.org/abs/2009.03779).
- Ransomware: [UNVEIL](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/kharaz), [CryptoDrop](https://www.cise.ufl.edu/~butler/pubs/icdcs16.pdf), [ShieldFS](https://doi.org/10.1145/2991079.2991110), [Redemption](https://theseclab.org/publications/raid2017redemption.pdf).
- Scripts and documents: [PowerShell deobfuscation](https://ics.uci.edu/~alfchen/pubs/zhenyuan_ccs19.pdf), [AMSI embeddings](https://arxiv.org/abs/1905.09538), [Survivalism](https://ieeexplore.ieee.org/abstract/document/9519480), [MEADE](https://arxiv.org/abs/1804.08162).
- Web and browser threats: [URLNet](https://arxiv.org/abs/1802.03162), [Phishpedia](https://www.usenix.org/conference/usenixsecurity21/presentation/lin), [VisualPhishNet](https://s-abdelnabi.github.io/VisualPhishNet/), [PhishIntention](https://www.usenix.org/conference/usenixsecurity22/presentation/liu-ruofan), [WebEval](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-jagpal.pdf), [Arcanum](https://www.usenix.org/conference/usenixsecurity24/presentation/xie-qinge).
- Reputation, signing, and testing: [CAMP](https://securitysteve.net/wp-content/uploads/2017/07/content-agnostic-malware-protection.pdf), [Certified Malware](https://users.umiacs.umd.edu/~tdumitra/papers/CCS-2017.pdf), [Certified PUP](https://software.imdea.org/~juanca/papers/malsign_ccs15.pdf), [AMTSO standards](https://www.amtso.org/standards/), [AV-TEST usability methodology](https://www.av-test.org/en/about-the-institute/test-procedures/test-modules-under-windows-usability/).
- Architectural limits: [BotHunter](https://www.usenix.org/conference/16th-usenix-security-symposium/bothunter-detecting-malware-infection-through-ids-driven), [Copilot](https://www.usenix.org/legacy/events/sec04/tech/full_papers/petroni/petroni_html/), [SubVirt](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/subvirt.pdf).

Only read-only repository inspection and web research were performed. No test suite, executable sample, phishing page, or malware dataset binary was run or downloaded.