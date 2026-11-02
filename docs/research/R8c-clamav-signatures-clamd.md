> **Claude verification (2026-11-02).** Codex gpt-6-sol, high, read-only, ClamAV 1.5.4 checkout.
> Confirmed: freshclam returns 0 only for up-to-date/success, otherwise the status code
> (`freshclam/freshclam.c:2198-2203`; `docs/man/freshclam.1.in:121-124`), so Sentinel accepting exit 1 is wrong.
>
> **RT numbering.** Codex numbered its new findings before seeing the registry. Registry ids:
> Codex RT-033 (`BC.Heuristics.*`) = registry **RT-028** (already recorded from R8a);
> Codex RT-028 → **RT-029**, RT-029 → **RT-030**, RT-030 → **RT-031**, RT-031 → **RT-032**, RT-032 → **RT-033**;
> RT-034, RT-035, RT-036 keep their numbers. The text below is Codex's, unchanged.

# R8c — ClamAV 1.5.4 signatures, updates, and clamd protocol

This is a read-only source review of the `clamav-1.5.4` checkout and Sentinel Guard’s current `clamav.py` and `scanner.py`. No daemon, updater, scan, or test was run. No completed R8a/R8b report was present under Sentinel’s `docs/research/`; that directory contained briefs only. The R5–R7 handoffs and the locked decisions in `PROJECT_CONTEXT.md` were read.

**Scope of the evidence:** “ClamAV detects” below means that a loaded rule can produce an engine alert under its applicable scan options and file parser. It does not mean that every input is fully inspected. In particular, a clamd `OK` reply contains no proof of recursive coverage, parser success for every member, or the database generation used for that request (`clamd/session.c:135-172`, `common/optparser.c:485-493`).

## 1. Signature database

### 1.1 Loader map

`cli_load()` dispatches by extension; directory discovery first filters with `CLI_DBEXT`. YARA entries exist only when built with `HAVE_YARA`. Unknown extensions are skipped (`libclamav/readdb.c:4706-4855`, `libclamav/readdb.h:39-130`).

| File type | Loader and meaning of a match or effect | Source |
|---|---|---|
| `.cvd`, `.cld`, `.cud` | `cli_cvdload()` opens a database container and loads its contained files. A reply names an inner rule, not the container. `.cud` is handled as unsigned; `.cvd` gets outer signature verification. | `libclamav/readdb.c:4749-4756`; `libclamav/cvd.c:511-523,585-620` |
| `.db` | `cli_loaddb()` loads legacy content patterns. A match is a byte-pattern detection. | `libclamav/readdb.c:1244-1320,4746-4747` |
| `.hdb`, `.hsb` | `cli_loadhash(..., HASH_PURPOSE_WHOLE_FILE_DETECT)`. Whole-file hash detection; the hash field length selects the algorithm, so the extension alone does not prove an algorithm. | `libclamav/readdb.c:2824-2837,2918-2925,4761-4762`; `libclamav/matcher-hash.h:34-38` |
| `.hdu`, `.hsu` | Same whole-file detection purpose, loaded in PUA mode only when `CL_DB_PUA` is set. | `libclamav/readdb.c:4763-4767` |
| `.mdb`, `.msb` | `cli_loadhash(..., HASH_PURPOSE_PE_SECTION_DETECT)`. PE-section hash detection, not a whole-file identity claim. | `libclamav/readdb.c:2834-2837,4771-4772`; `libclamav/matcher-hash.h:34-38` |
| `.mdu`, `.msu` | PE-section hash detection in PUA mode, conditional on `CL_DB_PUA`. | `libclamav/readdb.c:4776-4780` |
| `.imp` | `cli_loadhash(..., HASH_PURPOSE_PE_IMPORT_DETECT)`. A PE import-hash match; it does not identify the entire file byte for byte. | `libclamav/readdb.c:4773-4774`; `libclamav/matcher-hash.h:34-38` |
| `.fp`, `.sfp` | `cli_loadhash(..., HASH_PURPOSE_WHOLE_FILE_FP_CHECK)`. These are false-positive suppression hashes, not detections. A matched current or ancestor scan layer is marked trusted and its evidence removed. | `libclamav/readdb.c:4769-4770`; `libclamav/matcher.c:572-609,676-731` |
| `.ndb` | `cli_loadndb(..., sdb=0)`. Extended body/content signature with target and offset semantics. A match means the rule’s content condition held, not that a whole-file hash matched. | `libclamav/readdb.c:1634-1684,4782-4783` |
| `.ndu` | `.ndb` form in PUA mode, conditional on `CL_DB_PUA`. | `libclamav/readdb.c:4785-4789` |
| `.ldb` | `cli_loadldb()` and `load_oneldb()`. Logical expression over subsignatures; the final name is the logical rule’s name. | `libclamav/readdb.c:2095-2232,2275-2301,4791-4792` |
| `.ldu` | `.ldb` form in PUA mode, conditional on `CL_DB_PUA`. | `libclamav/readdb.c:4794-4798` |
| `.sdb` | `cli_loadndb(..., sdb=1)`. Specialized content-signature path. Its name alone does not disclose the specialized matching context. | `libclamav/readdb.c:4804-4805` |
| `.cbc` | `cli_loadcbc()` loads bytecode, conditional on `CL_DB_BYTECODE`. A plain unsigned `.cbc` is skipped unless unsigned bytecode is enabled; signed container bytecode can load. Bytecode may use a logical signature as its trigger. | `libclamav/readdb.c:2332-2403,4799-4803` |
| `.cdb` | `cli_loadcdb()` loads container metadata conditions: type, names, sizes, position, encryption flag and related fields. A match need not involve malicious bytes within a member. | `libclamav/readdb.c:3113-3155,3187-3247,4838-4839` |
| `.zmd`, `.rmd` | `cli_loadmd(type=1/2)` loads ZIP/RAR member metadata conditions, including name, encryption, sizes, compression method, member number and depth. | `libclamav/readdb.c:2957-3016,3025-3049,4807-4811` |
| `.idb` | `cli_loadidb()` populates an icon matcher; icon matching can be used in logical signature evaluation. It is visual/resource similarity evidence, not exact whole-file identity. | `libclamav/readdb.c:1320-1342,4835-4836`; `libclamav/matcher.c:767,961-970` |
| `.pdb`, `.gdb` | `cli_loadpdb()` loads domain-list regex rules for phishing, conditional on `CL_DB_PHISHING_URLS` and phishing engine configuration. | `libclamav/readdb.c:1613-1630,4824-4828` |
| `.wdb` | `cli_loadwdb()` loads the phishing URL allow-list matcher. Its effect is to permit a URL comparison, not report a malware match. | `libclamav/readdb.c:1593-1610,4819-4823` |
| `.ign`, `.ign2` | `cli_loadign()` loads signature-name exclusions, optionally tied to the MD5 of the **database entry**. It prevents selected rules from loading; it does not trust a scanned file. Both extensions share this loader. | `libclamav/readdb.c:2722-2818,4832-4833` |
| `.crb` | `cli_loadcrt()` loads certificate trust or block information, subject to certificate-scan configuration. This can affect PE certificate decisions; it is not a generic file-hash rule. | `libclamav/readdb.c:3323-3344,3397-3467,4758-4759` |
| `.cat` | `cli_loadmscat()` loads Microsoft catalog certificates/hashes when catalog and certificate parsing are enabled. Catalog-derived hashes can enter the FP matcher. | `libclamav/readdb.c:3491-3521,4840-4841`; `libclamav/asn1.c:2323-2336` |
| `.ioc` | `cli_loadopenioc()` passes OpenIOC content to `openioc_parse()`. The exact emitted rule depends on that parser, not the suffix alone. | `libclamav/readdb.c:3524-3531,4842-4843` |
| `.yar`, `.yara` | `cli_loadyara()`, when compiled with YARA and not excluded by `CL_DB_YARA_EXCLUDE`. Rules are converted into ClamAV matching structures; a reported identifier does not reveal the original condition or byte view. | `libclamav/readdb.c:4419-4530,4844-4850` |
| `.ftm` | `cli_loadftm()` adds file-type recognition patterns. It changes type selection and downstream parsing; it is not itself a malware verdict. | `libclamav/readdb.c:2469-2580,4829-4830` |
| `.info` | `cli_loadinfo()` verifies metadata and hashes for files inside a database container. It cannot be loaded as an ordinary standalone database. | `libclamav/readdb.c:2603-2629,2613-2615,4816-4817`; `libclamav/cvd.c:234-270` |
| `.cfg` | `cli_dconf_load()` changes dynamic engine configuration. Its effect is on what scanning features are active, not a detection. | `libclamav/readdb.c:4813-4814` |
| `.pwdb` | `cli_loadpwdb()` loads password entries for supported container contexts. The source stores the entries in `engine->pwdbs`; a name is explicitly **not stored** for the ignore check. Do not infer a malware-signature match from the mere presence of this file. | `libclamav/readdb.c:4540-4579,4646-4682,4851-4852` |

**Important loader conditions.** The directory loader orders `.ign/.ign2` first, then `daily.cld` or `daily.cvd`, `local.gdb`, `daily.cfg`, `.crb`, and ordinary databases. For a `daily.cld`/`daily.cvd` pair it selects the higher version, preferring CLD on a tie. Its comment says this duplicate treatment is not generalized to every CVD/CLD pair (`libclamav/readdb.c:5087-5214`). `OfficialDatabaseOnly` skips ordinary non-CVD/CLD files, but the source has a TODO questioning how `.ign/.ign2` and `local.gdb` should interact with that option (`libclamav/readdb.c:5151-5161`).

### 1.2 False positives, ignores, and a Sentinel trust list

| Mechanism | Exact scope | Gate v2 consequence |
|---|---|---|
| `.fp/.sfp` | During alert processing, `cli_check_fp()` hashes the current layer and ancestors. On a match it calls `cli_trust_layers()` for the matched layer through contained layers and returns `CL_VERIFIED` (`libclamav/matcher.c:588-709`; `libclamav/others.c:1634-1648`). | A clamd `OK` can mean an alert was suppressed by a trusted hash. The reply does not say this occurred (`clamd/session.c:135-172`). |
| `.ign/.ign2` | `cli_chkign()` normalizes a signature name and optionally checks MD5 of the rule line; matching rules are skipped **at load time** (`libclamav/readdb.c:1160-1189,2722-2818,2903-2904`). | Appropriate for a narrowly identified bad rule, with review and expiry. It is not a user-file allow list. |
| `.wdb` | Allow-list for phishing URL matching only (`libclamav/readdb.c:1593-1610`). | Not suitable for trusting arbitrary local files. |
| Sentinel’s current hash allowlist | `Scanner.scan_file()` returns before ClamAV, rules and Defender when `is_hash_allowed()` is true (`agent/sentinel/engine/scanner.py:95-100`). | It suppresses **all** later layers, a broader decision than a ClamAV FP entry. |

**Inference/design:** If Sentinel wants a ClamAV-native exception for a confirmed benign file, a size-bound SHA-256 `.sfp` entry in its private database directory is the closest model, followed by controlled reload and a harmless positive/negative check. Its trust scope must be explicit: an FP hit on a container ancestor can clear evidence in contained layers (`libclamav/matcher.c:593-709`). For an ordinary user “Trust” action, keep a Sentinel-owned path-plus-hash exception, as already decided in `docs/handoff/PROJECT_CONTEXT.md:139-142`; do not silently translate it into a broad ClamAV FP rule. Avoid `.ign2` for file trust because it disables a rule for other files too (`libclamav/readdb.c:1160-1189`).

## 2. Returned names and evidence strength

| Fact | Consequence |
|---|---|
| A loaded rule supplies its own name; `cli_virname()` returns the original for official loads and appends `.UNOFFICIAL` for nonofficial loads (`libclamav/readdb.c:101-125`). CVD/CLD inner rules are marked official; CUD is unsigned (`libclamav/cvd.c:585-620`). | `.UNOFFICIAL` identifies load provenance as represented by the engine. It says nothing about hash versus content matching or rule quality. |
| `cli_loadhash()`, `load_oneldb()`, container loaders and YARA conversion all construct names from their rule records (`libclamav/readdb.c:2219-2223,2918-2925,3025-3031,3167-3180,3860-3873`). | A name alone cannot reliably distinguish `.hdb` from `.mdb`, `.imp`, `.ndb`, `.ldb`, `.cdb`, bytecode, or YARA. The standard clamd reply has no database filename or signature-type field (`clamd/session.c:160-167`). |
| Internally, `cli_append_virus()` treats `PUA.`, `Heuristics.`, and `BC.Heuristics.` as potentially unwanted; `Weak.` as weak; other names as strong. Heuristic precedence can alter the potentially-unwanted path (`libclamav/others.c:1721-1740`; `common/optparser.c:431`). | Sentinel currently recognizes only the first two prefixes (`agent/sentinel/engine/clamav.py:228-233`). `BC.Heuristics.*` is incorrectly promoted to critical. A clamd string still does not expose the full internal `cl_verdict_t` or all evidence (`libclamav/clamav.h:84-92`; `clamd/session.c:160-167`). |
| ClamAV’s new scan API distinguishes `NOTHING_FOUND`, `TRUSTED`, `STRONG_INDICATOR`, and `POTENTIALLY_UNWANTED` (`libclamav/clamav.h:84-92`). | The clamd wire format compresses this richer result into `OK`, `FOUND`, or `ERROR` lines (`clamd/session.c:135-172`). |

**Grounding Sentinel’s locked policy.** `PROJECT_CONTEXT.md:127-138,249-253` calls for one conclusive signature to suffice, a weak-name denylist, PUA and heuristic restraint, and separate quarantine policy. Implement that as a **versioned policy over a parsed name and known database provenance**, with explicit weak precedence. Add `BC.Heuristics.*`, `Heuristics.Limits.Exceeded.*`, and encrypted-content alerts to nonconclusive or coverage categories (`libclamav/others.c:1721-1740`; `libclamav/others.c:1241-1259,1316`; `libclamav/pdf.c:3691`). Preserve `Generic`, `Gen`, and `Agent` as neither automatically weak nor proof of exact hash identity; the source permits arbitrary rule names across multiple loaders (`libclamav/readdb.c:4706-4855`). An official-looking family name remains a rule alert, not cryptographic proof that the whole file is known bad.

The only way to classify a particular signature’s **mechanism** conclusively is to associate its identifier with an indexed, verified database generation and its source record, or to use a richer trusted libclamav integration. `VERSION` gives the engine plus daily database version/time, not per-rule provenance (`clamd/session.c:484-499`).

## 3. CVD/CLD and freshclam

| Stage | Source-backed behavior | Readiness implication |
|---|---|---|
| CVD verification | `cli_cvdload()` verifies an outer CVD signature and returns `CL_EVERIFY` on failure (`libclamav/cvd.c:511-523`). `freshclam` downloads an optional versioned `.sign`, then calls `cli_cvdverify()`; absence of `.sign` can fall back to the legacy signature route, depending on FIPS limits (`libfreshclam/libfreshclam_internal.c:1532-1571`; `common/optparser.c:392`). | Record verification outcome and configuration. File existence is insufficient. |
| CLD verification | CLDs are patched CVDs and have no outer CVD signature (`libclamav/cvd.c:525-527`; `libfreshclam/libfreshclam_internal.c:2631-2640`). Container `.info` processing verifies an internal signature and the listed members’ SHA-256 checksums (`libclamav/readdb.c:2603-2629`; `libclamav/cvd.c:234-270,615-620`). | A CLD is a valid update product, but “signed” must be described precisely. |
| Incremental updates | With scripted updates, freshclam applies sequential `<database>-<version>.cdiff` patches to an unpacked local CVD/CLD, builds a CLD, and may fall back to full CVD on empty or failed patches (`libfreshclam/libfreshclam_internal.c:1642-1683,1745-1805,2519-2637`). | Do not require `.cvd` specifically after a successful update. |
| Partial or older updates | Source paths explicitly accept fewer patches than expected, or an older CVD than advertised, and log that choice (`libfreshclam/libfreshclam_internal.c:2590-2619`). | `freshclam` process success does not prove “latest advertised version.” Compare per-database local version and age with the update result. |
| `TestDatabases` | Default is enabled. Freshclam calls `fc_test_database()` before replacing the old database; it creates an engine, calls `cl_load()` with phishing, bytecode, PUA and enhanced options, and prepares bytecode when enabled (`common/optparser.c:579`; `freshclam/freshclam.c:283-303`; `libfreshclam/libfreshclam.c:463-513`; `libfreshclam/libfreshclam_internal.c:2644-2655`). | Keep enabled. This is load validation, not an end-to-end clamd scan or proof that the running daemon activated the generation. |
| Corruption | CVD open/verify, container `.info`, member checksum, or load failures produce errors (`libclamav/cvd.c:504-523,596-606`; `libclamav/cvd.c:234-270`). On reload failure clamd retains its previous engine (`clamd/server-th.c:1774-1801`). | Continue scanning with an identified old generation if policy allows, but report stale/degraded readiness. |
| Age policy | `FailIfCvdOlderThan` is a clamd startup check, in days, before `cl_load()` (`common/optparser.c:307`; `clamd/clamd.c:705-720`). `check_if_cvd_outdated()` compares against `cl_cvdgetage()` (`common/misc.c:498-513`). For a directory, `cl_cvdgetage()` takes the **minimum age** among CVD/CLD files, meaning the newest file can satisfy the check while another database remains old (`libclamav/cvd.c:917-988`). | Set a policy, but separately check `main`, `daily`, and enabled `bytecode`; do not treat this option as a complete per-database freshness guarantee. |
| Version exposed by clamd | `print_ver()` reads `CL_ENGINE_DB_VERSION` and `CL_ENGINE_DB_TIME`; these fields are set when a `daily.*` container loads (`clamd/session.c:484-499`; `libclamav/cvd.c:559-575`). | `VERSION` identifies the active **daily** generation, not every database or its checksum. |
| Return codes | Freshclam defines `FC_SUCCESS=0`, `FC_UPTODATE=1`, errors thereafter, but its executable returns process code **0** for either success or up-to-date and returns the error status otherwise (`libfreshclam/libfreshclam.h:69-90`; `freshclam/freshclam.c:2199-2203`). | Sentinel’s acceptance of process exit **1** is incorrect. |

**Gate v2 “ready” check, inference:** require (1) expected database inventory with parseable headers; (2) successful verification/load test of the candidate generation; (3) age and version recorded separately for `main`, `daily`, and enabled `bytecode`; (4) clamd identity verified under the owner’s locked anti-spoofing decision; (5) a completed reload confirmed by a subsequent active `VERSION` transition for daily and a harmless test-rule check for any local DB whose version is not exposed; (6) configured scan limits and feature flags recorded with the result. `PING` establishes only that a listener answered `PONG` (`clamd/session.c:582-587`), while `RELOAD` answers `RELOADING` before actual activation (`clamd/session.c:571-581`; `clamd/server-th.c:1766-1801`).

## 4. clamd protocol

### 4.1 Commands and framing

`zCOMMAND\0` requests use NUL-delimited replies; `nCOMMAND\n` uses newline. Some older unprefixed commands remain accepted, but `INSTREAM`, `ALLMATCHSCAN`, `IDSESSION` and `VERSIONCOMMANDS` require the modern framing. Unknown or invalid commands receive an error or `UNKNOWN COMMAND` and close the connection (`docs/man/clamd.8.in:11-14,40-49,63-82`; `clamd/session.c:75-130,642-653`).

| Command | Input and response; useful limits | Sentinel value |
|---|---|---|
| `PING` | `PONG`; session responses gain request ID (`clamd/session.c:582-587`). | Liveness only. |
| `VERSION` | Engine version, active daily DB version and timestamp when present; can return `COMMAND UNAVAILABLE` (`clamd/session.c:484-499,588-597`). | Active daily generation, with caveats above. |
| `VERSIONCOMMANDS` | Version plus `COMMANDS:` list; parser lists all compiled command strings, so listing alone does not prove a command is enabled by configuration (`clamd/session.c:502-518,599-603`). | Protocol compatibility check; not policy attestation. |
| `STATS` | Queue, active tasks and memory; format is not stable and can be disabled (`docs/man/clamd.8.in:58-61`; `clamd/session.c:622-628`). | Health/backpressure, **not** per-scan evidence. |
| `RELOAD` | `RELOADING` acknowledges a queued reload; may return `COMMAND UNAVAILABLE` (`clamd/session.c:571-581`). | Trigger only; verify later activation. |
| `SHUTDOWN`, legacy `QUIT` | Shutdown control, subject to configuration (`clamd/session.h:25-35`; `clamd/session.c:562-570`). | Process control; a same-user listener is a trust concern. |
| `SCAN path` | Daemon opens a full path; default first-result scan (`docs/man/clamd.8.in:31-32`; `clamd/session.c:447-455`). | Not preferred for Sentinel’s byte-identity contract. |
| `CONTSCAN path` | Continue across files in a directory after a detection (`docs/man/clamd.8.in:34-35`). | Directory traversal behavior, not all signatures within one file. |
| `MULTISCAN path` | Parallel directory scan; a file falls back to regular scan (`docs/man/clamd.8.in:37-38`). | No advantage for one INSTREAM object. |
| `ALLMATCHSCAN path` | Continues after a match **within a file**; must use `n`/`z`, can be disabled, and takes a pathname (`docs/man/clamd.8.in:40-43`; `clamd/session.c:363-371`). | Can reveal multiple names, but there is **no `ALLMATCHINSTREAM` command** in the command table (`clamd/session.c:75-100`). Path scanning would weaken Sentinel’s byte binding. |
| `INSTREAM` | After `zINSTREAM\0`, each chunk is a four-byte network-order unsigned length plus bytes; zero length ends the stream. Exceeding `StreamMaxLength` returns `INSTREAM size limit exceeded. ERROR` and closes (`docs/man/clamd.8.in:45-49`; `clamd/server-th.c:827-870`). | Correct transport for Sentinel’s in-memory bytes; reply remains terse. |
| `FILDES` | Unix-domain socket descriptor passing; not available over Sentinel’s Windows TCP connection (`docs/man/clamd.8.in:51-56`; `clamd/session.c:70-72`). | Not an available Windows alternative. |
| `IDSESSION`, `END` | Several requests on one socket, asynchronous numbered replies. `CONTSCAN`, `MULTISCAN`, `ALLMATCHSCAN`, `RELOAD` and `SHUTDOWN` are rejected inside; client must read replies to avoid deadlock (`docs/man/clamd.8.in:63-73`; `clamd/session.c:539-558`). | Connection reuse only; no richer scan result. |
| `DETSTATS`, `DETSTATSCLEAR` | Names remain in the parser, but implementation comments say the commands have been removed and return without useful output (`clamd/session.c:98-100,605-611`). | Do not build on them. |
| `STREAM`, old `SESSION` | Documented as removed/unsupported (`docs/man/clamd.8.in:85-94`). | Do not use. |

A normal virus line is `<path>: <name> FOUND`; errors end in `ERROR`; an `IDSESSION` prefix adds `<id>:` (`clamd/session.c:135-172`). `ExtendedDetectionInfo` adds hash/size to **daemon logs**, not the normal wire reply (`clamd/scanner.c:110-132,314-345`). Thus one ordinary INSTREAM reply tells a client whether that scan returned `OK`, one reported name, or an error. It cannot identify the rule’s source file/type, show all matches, report skipped members or byte ranges, distinguish trusted FP suppression from an ordinary `OK`, or attest to a completed reload (`clamd/session.c:135-172,339-362`; `libclamav/matcher.c:676-709`).

### 4.2 Limits relevant to a reply

Sentinel writes `StreamMaxLength 401M`, `MaxFileSize 401M`, `MaxScanSize 1600M`, `MaxRecursion 17`, `MaxFiles 10000`, and `MaxScanTime 120000` (`agent/sentinel/engine/clamav.py:96-101`). `StreamMaxLength` controls transport acceptance; the others govern scanning of the input and extracted objects (`common/optparser.c:334,485-493`). They are different limits. With `AlertExceedsMax no`, ordinary `OK` is compatible with internal limit exhaustion (`agent/sentinel/engine/clamav.py:108`; `libclamav/others.c:1241-1259,1316,1792`). Even with alerts enabled, a limit name is coverage evidence, not proof of malicious content.

## 5. Sentinel mapping and RT findings

### 5.1 Adapter walk-through

| Sentinel location | What it does | Source comparison |
|---|---|---|
| `clamav.py:75-77` | Checks only presence of `main` and `daily` CVD/CLD paths. | Loader may reject corrupt databases; enabled bytecode is not checked (`libclamav/cvd.c:504-523,596-606`; `libclamav/readdb.c:4799-4803`). |
| `clamav.py:84-123` | Writes private clamd/freshclam configs. | INSTREAM size, parser limits, alerts and PUA policy are fixed here. `TestDatabases` is omitted but defaults on (`common/optparser.c:579`). |
| `clamav.py:127-148` | Runs freshclam, accepts exit 0 or 1, tests only file presence, sends `RELOAD`, ignores its reply and connection failure. | Process exit 1 is an error; `RELOADING` precedes activation; old engine can remain (`freshclam/freshclam.c:2199-2203`; `clamd/session.c:571-581`; `clamd/server-th.c:1766-1801`). |
| `clamav.py:161-176` | One TCP connection for `PING`/`VERSION`; read until NUL or EOF. | Correct modern framing, but `PING` gives liveness only and `VERSION` gives daily version/time (`clamd/session.c:582-603,484-499`). |
| `clamav.py:178-202` | Sends `zINSTREAM\0`, 256 KiB chunks with network-order lengths and zero terminator. | Matches protocol (`docs/man/clamd.8.in:45-49`; `clamd/server-th.c:827-870`). |
| `clamav.py:205-225` | Reads up to 64 KiB; accepts EOF before NUL; treats any text ending ` FOUND` as a detection; strips only a leading `stream:`. | The actual response grammar includes explicit status and terminator; non-INSTREAM/path/session replies should not be accepted as a normal scan result (`clamd/session.c:135-172`). |
| `clamav.py:228-233` | Makes only `Heuristics.*` and `PUA.*` medium; all else critical. | Misses `BC.Heuristics.*` and cannot infer mechanism from name (`libclamav/others.c:1721-1740`; `libclamav/readdb.c:4706-4855`). |
| `clamav.py:248-265` | Calls a recent `PING` “ready,” cached for ten seconds. | It does not attest database age, selected generation, configuration, or daemon identity (`clamd/session.c:582-587`; `libclamav/cvd.c:559-575`). |
| `clamav.py:306-344` | Scans bytes or a path re-read; truncates files above 400 MiB; maps `OK` to `clean`. | INSTREAM itself has no coverage report; file and recursive limits can yield an apparently clean reply (`clamd/session.c:135-172`; `common/optparser.c:485-493`). |
| `scanner.py:58-65,86-93` | Cache key includes rule counts, YARA count, ClamAV `VERSION`, Defender availability. | Counts do not identify rule contents; daily `VERSION` does not identify every loaded DB; cached results may outlive a local-rule change (`clamd/session.c:484-499`). |
| `scanner.py:95-100` | A user hash allow skips all remaining layers. | Broader than ClamAV FP or ignore semantics (`libclamav/matcher.c:676-709`; `libclamav/readdb.c:1160-1189`). |
| `scanner.py:125-137` | Adds ClamAV’s status and one finding; oversized path is re-read and checked by size/mtime afterwards. | This does not bind the re-read bytes to the earlier SHA-256 against same-size, restored-mtime replacement. INSTREAM binds only bytes actually sent (`agent/sentinel/engine/clamav.py:182-202`). |
| `scanner.py:139-153` | Defender may be skipped after a malicious ClamAV classification; result is stored. | Weak-name misclassification can suppress an independent layer (`agent/sentinel/engine/clamav.py:228-233`). |

### 5.2 Findings registry

These are source-review findings with **proposed harmless tests**. No tests were executed in this round.

| ID | Finding and exact condition | Harmless test |
|---|---|---|
| **RT-001** | Reuse: any name outside `Heuristics.*`/`PUA.*` becomes critical, including `BC.Heuristics.*` and potentially weak or ambiguous names (`agent/sentinel/engine/clamav.py:228-233`; `libclamav/others.c:1730-1740`). | Inject fake clamd replies for ordinary, `BC.Heuristics.*`, PUA, limit and weak names; assert separate detection/quarantine decisions. |
| **RT-004 / RT-012 / RT-014** | Reuse: oversized/recursive/encrypted portions may remain uninspected while an `OK` becomes clean; `AlertExceedsMax no` and `AlertEncrypted no` hide useful coverage alerts (`agent/sentinel/engine/clamav.py:96-108,339-343`; `common/optparser.c:451-457,485-493`). | Synthetic nested and encrypted benign containers, plus fake limit replies; assert partial/unknown coverage. |
| **RT-005** | Reuse: large files are hashed, then reopened for ClamAV; size/mtime comparison does not prove identical bytes (`agent/sentinel/engine/scanner.py:79-80,125-135`; `agent/sentinel/engine/clamav.py:182-193`). | Swap two harmless same-size byte sequences between stages and restore mtime. |
| **RT-009** | Reuse: cache identity uses rule counts and daily `VERSION`, neither of which represents all rule/database content (`agent/sentinel/engine/scanner.py:58-65,86-93`; `clamd/session.c:484-499`). | Replace one harmless local rule with another while preserving count; assert cache invalidation. |
| **RT-010** | Reuse: update success is not tied to activation or per-DB freshness (`agent/sentinel/engine/clamav.py:127-148`; `clamd/server-th.c:1766-1801`). | Fake old `VERSION` after `RELOADING`; assert degraded readiness and retry. |
| **RT-013** | Reuse: unavailable/error returns no conclusive finding, while `OK` is treated as clean and the top result may remain clean (`agent/sentinel/engine/clamav.py:328-344`; `agent/sentinel/engine/scanner.py:125-137`). | Fake timeout and connection errors with no other findings; assert overall unknown. |
| **RT-028** | **New:** `update()` accepts freshclam exit 1 as success when old DB files exist, though executable exit 1 is not its up-to-date result (`agent/sentinel/engine/clamav.py:141-148`; `freshclam/freshclam.c:2199-2203`). | Fake subprocess exit 1 with pre-existing harmless DB paths; assert error. |
| **RT-029** | **New:** `RELOAD` response is ignored; `RELOADING` is accepted before the new engine is active, and failed reload retains the old engine (`agent/sentinel/engine/clamav.py:144-148`; `clamd/session.c:571-581`; `clamd/server-th.c:1787-1801`). | Fake `RELOADING`, then unchanged `VERSION`; assert not updated. |
| **RT-030** | **New:** `has_database()` does not verify headers, signatures or bytecode inventory; `ready()` relies on `PING` (`agent/sentinel/engine/clamav.py:75-77,255-265`; `libclamav/cvd.c:504-523`). | Stub `PING=PONG` with missing/corrupt candidate DB metadata; assert not fully ready. |
| **RT-031** | **New:** `parse_reply()` accepts a `FOUND` suffix without requiring the expected `stream:` frame, and `_recv_reply()` permits EOF before NUL (`agent/sentinel/engine/clamav.py:205-225`; `clamd/session.c:135-172`). | Feed truncated, wrong-prefix, extra-line and missing-terminator benign strings; assert protocol error. |
| **RT-032** | **New:** local `.fp/.sfp`, `.ign2`, `.wdb`, or other DB/config changes are not represented by clamd’s daily-only `VERSION`, so a cached result may survive a changed rule policy (`agent/sentinel/engine/scanner.py:58-65,86-93`; `clamd/session.c:484-499`; `libclamav/readdb.c:4706-4855`). | Change a harmless local DB file with fixed daily version; assert generation change. |
| **RT-033** | **New:** the current prefix rule misses `BC.Heuristics.*`, while the ClamAV engine explicitly puts that prefix on its potentially-unwanted path (`agent/sentinel/engine/clamav.py:228-233`; `libclamav/others.c:1730-1739`). | Fake `stream: BC.Heuristics.Test FOUND`; assert nonconclusive evidence. |
| **RT-034** | **New:** `FailIfCvdOlderThan` is absent, and even if added it checks the youngest CVD/CLD in a directory rather than every required DB (`agent/sentinel/engine/clamav.py:84-111`; `common/misc.c:498-513`; `libclamav/cvd.c:953-981`). | Synthetic header metadata with fresh daily and stale main; assert degraded readiness. |
| **RT-035** | **New:** after a ClamAV result classified malicious, Defender is skipped; a weak-name policy error therefore also removes corroborating evidence (`agent/sentinel/engine/scanner.py:139-148`; `agent/sentinel/engine/clamav.py:228-233`). | Inject a weak ClamAV name on a harmless risky-type fixture; assert Defender remains eligible under Gate v2. |
| **RT-036** | **New:** no schema records whether an `OK` may reflect an FP/ancestor trust rule, internal limit, or simply no match; the clamd reply cannot supply those distinctions (`agent/sentinel/engine/clamav.py:217-225,339-343`; `libclamav/matcher.c:676-709`; `clamd/session.c:135-172`). | Model each condition with a fake reply and explicit adapter coverage inputs; assert `OK` alone never upgrades incomplete coverage. |

**Not a finding:** R5’s RT-015 path-quoting concern was rejected in the handoff; this review did not reclassify it as a defect. The protocol framing and four-byte INSTREAM chunk encoding currently used by Sentinel match the documented protocol (`agent/sentinel/engine/clamav.py:195-202`; `docs/man/clamd.8.in:45-49`).

# Implications for Gate v2

The following is a **proposed adapter contract**, not an existing ClamAV API. It implements Sentinel’s locked separation of engine status, verdict, evidence, and quarantine decision (`docs/handoff/PROJECT_CONTEXT.md:122-138`).

| Field | Required representation |
|---|---|
| **Input identity** | Immutable bytes or a held file handle/snapshot; SHA-256, exact size, source path only as context, and byte range sent. For a 400 MiB prefix scan, record `[0, 400 MiB)` and `partial_by_policy` (`agent/sentinel/engine/clamav.py:310-316`; `agent/sentinel/engine/scanner.py:125-135`). |
| **Daemon identity** | Verified listener/process identity according to the owner’s R3 decision; unverified replies may inform a notification but must not establish clean coverage or automatic quarantine (`docs/handoff/PROJECT_CONTEXT.md:238-244`). |
| **Database identity** | Active engine version; active daily version/time from `VERSION`; separately inventoried and verified `main`, `daily`, enabled `bytecode`, local DB file hashes, configuration hash, and successful reload generation. `VERSION` alone is insufficient (`clamd/session.c:484-499`; `libclamav/cvd.c:559-575`). |
| **Transport status** | `completed`, `partial_by_policy`, `partial_runtime`, `skipped`, `unavailable`, `timeout`, `protocol_error`, `scan_error`. Preserve raw bounded reply and a parsed error code/text (`clamd/session.c:135-172`; `clamd/server-th.c:862-870`). |
| **Coverage** | Exact top-level bytes sent; configured `StreamMaxLength`, `MaxFileSize`, `MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`; observed `Heuristics.Limits.Exceeded.*` or encryption alerts. Recursive completeness is **unknown** when only ordinary INSTREAM `OK` is available (`common/optparser.c:334,451-457,485-493`; `clamd/session.c:135-172`). |
| **Detection evidence** | Raw name, normalized identifier, `.UNOFFICIAL` marker, policy version, category (`strong_candidate`, `pua`, `heuristic`, `limit`, `encrypted`, `weak`, `unknown`), and source confidence. Do not label an alert “exact hash” without DB-record provenance (`libclamav/readdb.c:101-125,4706-4855`; `libclamav/others.c:1721-1740`). |
| **Readiness** | Separate `transport_ready`, `database_loaded`, `database_fresh`, `database_verified`, `reload_confirmed`, `daemon_verified`, and `configuration_acceptable`. `PING` contributes only to the first (`clamd/session.c:582-587`; `clamd/server-th.c:1766-1801`). |
| **Verdict and action** | ClamAV evidence feeds the global Gate v2 verdict. Weak/PUA/heuristic/coverage alerts cannot alone imply malicious; a conclusive trusted signature may. Auto-quarantine is a later, separate decision with reason codes (`docs/handoff/PROJECT_CONTEXT.md:127-138`; `libclamav/others.c:1721-1740`). |

The practical constraint is sharp: **the current clamd INSTREAM interface provides reliable byte transport and a terse scan result, but no per-request rule type, all-match stream mode, or coverage proof** (`docs/man/clamd.8.in:40-49`; `clamd/session.c:75-100,135-172`). Gate v2 should preserve those unknowns in its contract instead of manufacturing precision from a name or an `OK`.