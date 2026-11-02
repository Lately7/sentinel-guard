You are a research scientist doing a literature review for Sentinel Guard, the
repository owner's own Windows 11 anti-malware prototype (user-mode Python
agent, no kernel driver, no admin rights; MV3 browser extension for Helium).
Read-only: do NOT modify, create or delete any file. Use web search.

Read first: docs/ROADMAP.md, docs/handoff/PROJECT_CONTEXT.md (sections 7 and 11
are locked decisions), docs/handoff/codex-research-r5.md and, if present,
docs/handoff/codex-product-r6.md (do not repeat them; build on them).

## Question

Which published research (peer-reviewed papers, preprints with strong
evidence, test-lab methodology, vendor research with data) can make Sentinel
detect more real threats with few false positives, given its architecture?

## Coverage

For each threat class, summarise in a few lines how it typically reaches and
behaves on a Windows home PC, and which detection approaches the literature
supports:
1. File infectors / classic viruses and worms
2. Trojans, droppers, downloaders, loaders
3. Ransomware
4. Infostealers and credential theft (including browser data)
5. Fileless / script-based and living-off-the-land abuse (PowerShell, WSH,
   LNK, HTA, Office macros, OneNote, ISO/IMG/ZIP delivery)
6. Remote access trojans and botnets
7. Cryptominers and cryptojacking (including in-browser)
8. Adware / PUA / malicious browser extensions
9. Phishing and malicious web pages (URL, page content, brand impersonation)
10. Rootkits/bootkits (only to state what user mode cannot see)

Detection techniques to assess (include others you find):
- Static ML on PE files (e.g. EMBER and its successors, byte-level CNNs such as
  MalConv, gradient-boosted feature models), concept drift and time-aware
  evaluation, false-positive control at low FPR operating points.
- Fuzzy / similarity hashing (ssdeep, TLSH, imphash, section hashing) for
  variant detection; YARA rule quality and false-positive research.
- Authenticode, reputation and prevalence signals.
- Ransomware detection from file-system activity (entropy change, rename
  bursts, canary/decoy files) and what is possible without a driver.
- Script/document analysis (macro, PowerShell deobfuscation, AMSI-related
  research at a conceptual level).
- Phishing URL and page detection (lexical, visual similarity, ML), browser
  extension threat research.
- Evaluation methodology: datasets, temporal splits, FP measurement on clean
  software corpora, how test labs measure.
Adversarial ML may be discussed only defensively (robustness, what not to
rely on); do not describe how to construct evasive samples.

## Output

1. One table per threat class: approach, key papers (authors, year, venue),
   reported result and its caveats, applicability to Sentinel
   (direct / adaptable / not feasible in user mode) with one-line reason.
2. Top 10 improvements for Sentinel, ranked by expected detection gain per
   unit of effort and false-positive risk. For each: what to build, which
   module and roadmap phase (docs/ROADMAP.md), data needed and its licence,
   and a harmless experiment to validate it (synthetic data, feature-only
   datasets, clean-software corpora; never live malware binaries).
3. Datasets and tools usable safely: licence, whether they contain live
   binaries (flag clearly; Sentinel must not download live samples), and what
   can be used instead (features, hashes, metadata).
4. Open questions where the evidence is weak.

## Rules

- Read-only. Never claim a command ran unless you ran it and saw the result.
- No malware downloads, no sample links, no evasion or bypass instructions.
- Prefer primary sources; give a URL (DOI, arXiv, USENIX/NDSS/IEEE S&P/CCS/ACSAC,
  RAID, DIMVA, lab reports) for every claim; mark old or contested results.
- Answer in English, Markdown, concise, with a "Sources" list at the end.
