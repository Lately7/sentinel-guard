# Codex task — Gate v2 milestone 5, round 2: fix K1–K17

Your first round was cut off when the previous session ended, before you wrote
an answer. Claude committed what you had (`3cdb0de`, scope clean, 236 passed,
1 failed) and reviewed every line. Claude reproduced K1–K5, K7, K8, K10–K12 and
K14 by running them with synthetic input; the others come from reading the code.

## Pinned start

Worktree `..\sentinel-guard-gate-v2`, branch `codex/gate-v2-m5`, HEAD
**3cdb0de**; otherwise stop and report.

## Allowed paths

`agent/sentinel/gate_v2/` and `tests/gate_v2/` only. M1–M4 modules change where
a finding says so; list each change. `agent/sentinel/engine/` and everything
else are read-only. Do not commit. Another round is writing
`gate_v2/cache.py`, `gate_v2/legacy.py` and `tests/gate_v2/test_m6_*.py` in a
different worktree: do not create those files.

**Sandbox note:** you cannot run pytest in this sandbox (temp folder denied).
That is *not* a reason to stop: implement everything, re-read your code against
each test, and say which test covers what. Never create temp or probe folders.
Claude runs the suites and runs your new tests against `3cdb0de`: each must fail
there and pass after.

## Findings

Severity order. Each needs a test unless it says otherwise. Keep comments about
*why*, not what.

**K1 — a named detection becomes ERROR (`defender.py:250-251`).** `len(names) == 1`
rejects two threats, and the same name listed twice: both give
`THREAT_NAME_MISSING_OR_INVALID`, `unknown`, no evidence. The old parser used a
set. Dedupe; every valid name becomes evidence; invalid names beside a valid one
must not discard the valid one; only "no valid name at all" is `ERROR`. Cap at
16 names and record a limit when exceeded. `evidence_id` must be unique per name
(`defender.<sha256(name)[:24]>`, as in `clamd.py`).

**K2 — every file under a non-ASCII path becomes ERROR (`defender.py:174,243-246`).**
`_run` decodes as UTF-8 with `errors="replace"` and the adapter rejects U+FFFD.
MpCmdRun prints the scanned path in the console code page (`Scanning <path> found
no threats.`), so on this owner's Vietnamese-language paths each clean file is
`OUTPUT_INVALID`. Reproduced: `_run` on a child that writes `T\xe0i` returns
U+FFFD, the adapter returns `ERROR`. Decode in `_run` with a total single-byte
mapping (`latin-1`): nothing but the ASCII threat name is ever consumed. Keep the
adapter's garbled-output rule for injected runners (control characters,
over-long). Comment that the real output could not be checked here because
Defender is passive on this machine.

**K3 — a named detection is discarded on a generation mismatch
(`defender.py:271-276`, `orchestrator.py:193-196`).** Both layers drop the
evidence, so a named threat followed by the file vanishing (the normal result
when a real-time AV removes it) leaves no trace. Reproduced: `CHANGED`, no
evidence. Keep the evidence, status `CHANGED`, verdict `UNKNOWN`, empty coverage
(`dataclasses.replace` in the orchestrator, not `_synthetic`). `policy.decide`
then adds `UNACCEPTED_DETECTION`: never clean, not cacheable, no quarantine.

**K4 — a named detection after the deadline is discarded (`defender.py:241-242`).**
G2 again: the deadline is checked before parsing. Parse first. Only a *negative*
that arrives late becomes `TIMEOUT`; a late named threat keeps its evidence.

**K5 — stage says suspicious, final decision says trusted clean
(`analyzers/__init__.py:34-36`, `policy.py:102`).** Reproduced: core clean + a LNK
starting `cmd.exe` with arguments → `lnk` stage `suspicious`, final `clean`,
`trusted_clean=True`. R11 §6: such signals are "`suspicious` only when an explicit
rule says so". Add that explicit rule in `policy.py`: a named constant of
`detail_code`s, `LNK_TARGETS_SCRIPT_HOST` and `ORIGIN_BLOCKLISTED`, at
`Strength.SUPPORTING`, counted as weak with reason `CONTEXT_RULE`. Origin evidence
has no byte ranges, so `scope == "origin"` skips the range check; every other
acceptance condition stays. Never `malicious`, never quarantine (invariant 6).
Add `ORIGIN_BLOCKLISTED`: `MotwAdapter(reader, url_check: Callable[[str], bool] |
None = None)` tests `HostUrl` then `ReferrerUrl`; a raising `url_check` is ignored
with a coverage reason. The URL never enters evidence or events. Without this,
M6 would lose the old `origin.blocklisted_source` finding. The adapter's own
verdict must agree with the policy: `SUSPICIOUS` only for those two codes.

**K6 — Defender PUA names are conclusive (`defender.py:253-254`; invariant 6).**
`PUA:Win32/...` would quarantine. Add `classify_defender_name(name) -> (Category,
Strength)` in `policy.py`, beside `classify_clamav_name`, on the prefix before the
first `:`. `PUA*`, `Adware`, `BrowserModifier`, `Program`, `SoftwareBundler`,
`SettingsModifier`, `Misleading`, `MonitoringTool`, `RemoteAccess`, `Joke` →
`PUA`/`SUPPORTING`; `HackTool`, `VirTool`, `Constructor` → `RISKWARE`/`SUPPORTING`;
anything else, including no prefix → `MALWARE`/`CONCLUSIVE` (locked owner policy:
a named Defender threat is conclusive). `EICAR_Test_File` sets `is_test_file`.
The stage verdict is `SUSPICIOUS` for supporting evidence.

**K7 — coverage claims reads other stages made (`signer.py:132`; H1).** The
orchestrator passes one `BoundReader` to all bound stages and `reader.ranges` is
their union. Reproduced: core then signer on a 2 MiB PE → signer claims
`(0, 2097152)` having read 4096 bytes. Add `BoundReader.begin_stage()` clearing
the recorded reads; the orchestrator calls it before each `scan_bound`.

**K8 — one hung trust call stalls every later scan (`signer.py:108`).** Reproduced:
with a hung trust callable, each later scan waits its whole deadline in
`_TRUST_SLOT.acquire`, and that wait ignores cancellation. Take the slot without
blocking (at most 0.2 s, polling cancel); busy → `unavailable` at once. Test: a
second scan with a 1 s deadline returns in under 0.5 s.

**K9 — unbounded, uncancellable rehashing (J1; `defender.py:274`, `signer.py:145,155`,
`motw.py:99,103`, `orchestrator.py:194`).** `identity.revalidate` is called without
`cancel` and `max_bytes`; a 500 MiB file is rehashed up to three more times per
adapter.
* Orchestrator: pass a token that is also cancelled past the request deadline to
  both revalidations, and pass `max_bytes`. Keep a returned result's evidence when
  this check stops early (status `CANCELLED` or `TIMEOUT`, K3 rules).
* Defender adapter: `rehash=False` with `cancel`; the orchestrator owns the byte check.
* Signer: no path revalidation. Give the trust check the measured handle:
  `TrustCheck = Callable[[str, int | None], TrustState]` and
  `WINTRUST_FILE_INFO.hFile` (`pcwszFilePath` must stay non-null, use
  `measured.canonical_path or request.path`). Add `BoundReader.os_handle() -> int |
  None`. The handle is deny-write (H2), so the measured generation is what is
  verified, and this also works in the restricted worker, which must not open
  paths; R13b P4 forbids PE parsing in the privileged service. No handle →
  `unavailable`.
* MotW: `rehash=False`. The stream is not part of the content hash.

**K10 — every ordinary file is "malformed LNK" (`lnk.py:40-41,98-100`).** Reproduced:
a text file gives `PARTIAL`/`LNK_MALFORMED`. Since `decide` counts any stage that
is not completed or fixed-partial as non-deterministic, nothing would be cacheable
in M6. Read the 76-byte header first. Wrong size or CLSID → `COMPLETED`/`NOT_LNK`,
coverage only those bytes (like `NOT_PE`). A real LNK above `MAX_LNK` is parsed
from the first `MAX_LNK` bytes as `fixed_partial`, not skipped.

**K11 — target and arguments checks are easy to miss (`lnk.py:34-35,64-65,82`).**
Reproduced: `cmd.exe` with 5,000 spaces before its arguments → `LNK_MALFORMED`, no
evidence. These are structural observations of a harmless kind; keep them bounded.
* A string over the limit keeps its first 8192 bytes, advances by the declared
  length, and sets the parser state to partial instead of failing the parse.
* Test every target candidate, not `strings.get(8) or target`: RelativePath,
  LocalBasePath, LocalBasePath + CommonPathSuffix, Unicode variants, and
  `EnvironmentVariableDataBlock` (signature `0xA0000001`; `TargetAnsi` at +8,
  `TargetUnicode` at +268) from a bounded ExtraData walk (at most 64 blocks).
* Links with only a LinkTargetIDList: search its bytes, ASCII and UTF-16LE,
  case-insensitively, for the host basenames.
* Arguments count as present from the declared length even when truncated.
Tests: padded within and beyond `MAX_LNK`, base + suffix, relative path naming a
harmless file while LocalBasePath names the host, environment block, IDList only.
The LinkInfo branch has no test today; these cover it.

**K12 — no MotW is normal, not an unavailable engine (`motw.py:28-29,106-108`).**
Reproduced: a local file gives `UNAVAILABLE`/`ZONE_STREAM_ABSENT`, with a terminal
event per file. `read_zone` returns `None` only for `FileNotFoundError` →
`COMPLETED`/`NO_ORIGIN`. Any other `OSError` propagates → `ERROR`/`MOTW_READ_ERROR`.
Decode a UTF-16 BOM. Read bounded bytes, then decode.

**K13 — the policy carve-out has no test of its own (`policy.py:154-157`).** Replace
the inline condition with a named constant of engines whose declared coverage is
accepted, and drop the duplicated status test. Tests: Defender declared + full +
completed → trusted clean; another engine declared → `UNCERTAIN_COVERAGE`; Defender
declared with limits or opaque objects → incomplete.

**K14 — `test_swapped_before_defender_stage` never swaps.** `os.replace` over the
file held by `BoundReader` raises `PermissionError` (WinError 5, Claude checked),
the orchestrator turns that into `ADAPTER_ERROR`, and Defender runs on the
unchanged file. Rename the original away, then rename the replacement in; both
work while the reader holds the file.

**K15 — the real runner has no test, and G8 again (`defender.py:60-183`,
`signer.py:59-92`).** Move ctypes structures and bindings to module level (a small
`gate_v2/winjob.py` is fine; do not import `sentinel.service`). Close `stdout` on
every path. Windows-only tests using harmless `sys.executable -c` children: exit
code and bytes pass through; deadline kills the child and a grandchild (the venv
`python.exe` is itself a launcher, so the job is what proves this); cancel does the
same; output above `MAX_OUTPUT` → `ERROR`. Claude runs these. One test may call
`win_verify_trust` on `sys._base_executable` and skip if the result is `unavailable`.

**K16 — applicability seam (`defender.py:33-57,203-213`).** `self.applicability is
_applicability` means fakes never see the deadline: make it `Callable[[int | None],
tuple[str | None, str]]` returning a state (`active`, `passive`, `unknown`). A
transient PowerShell failure must not be cached 600 s as `PASSIVE`: `unknown` gets
readiness `APPLICABILITY_UNKNOWN`, stays `UNAVAILABLE`, and is retried after 30 s.
Call `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` by absolute
path. Sort `Platform\*` by numeric version tuple: string order puts `4.18.9999`
above `4.18.25000`. Honour cancel while waiting. Guard the cache with a lock.

**K17 — argv path and Defender pool (`defender.py:237`; R11 §3).** Pass
`measured.canonical_path or request.path`: `request.path` may be an alias or
relative. Add the one-slot Defender pool: a process-wide semaphore, waited on with
cancel and the deadline; a stage that cannot get it is `TIMEOUT`. Test with two
threads.

## Your answer

English, concise: per finding the change (file:line) and the test that covers it;
changes to M1–M4 files; anything not finished; open points for M6.
