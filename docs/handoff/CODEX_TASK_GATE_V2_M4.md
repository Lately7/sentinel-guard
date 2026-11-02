# Codex task — Gate v2 milestone 4: ClamAV adapter

You are the implementer of Gate v2. Claude reviews every line, runs the
tests and merges. Milestones 1–3 are merged; read their review records in
`REVIEWS.md` (F, G, H findings) — do not repeat those mistakes (in particular
H1 "inspected without checking", H7 "cap drops a conclusive hit", F1
"dropped detection becomes clean").

## Pinned start

Worktree `..\sentinel-guard-gate-v2`, branch `codex/gate-v2-m4`, start
commit **18454a9**; otherwise stop and report.

## Allowed paths

`agent/sentinel/gate_v2/` and `tests/gate_v2/` only (new `clamd.py`, and a
small `winnet.py` if you need the TCP owner table). M1–M3 modules change only
where M4 needs it; list each change. `agent/sentinel/engine/clamav.py` and
everything else outside `gate_v2/` is **read-only** (integration is
milestone 6). Do not commit.

## Read first

R11 §1 rows on ClamAV, §2, §5 row ClamAV + "Readiness detail for ClamAV",
§6, §7 rows Fake clamd / Real clamd, §9 rows "Clamd ownership check" and
"ClamAV opaque-container treatment"; `docs/research/R8a-*`, `R8b-*`,
`docs/research/R8c-clamav-signatures-clamd.md` §§2–5 (RT-030…RT-036);
`REVIEWS.md` RT-012, RT-013, RT-028, RT-030…RT-036; current client
`engine/clamav.py:153-235`; `docs/research/R13b-design-discussion.md` P4
(the service streams bounded raw chunks to clamd and parses only the reply —
no file-format parsing in this adapter).

## What to build: `ClamdAdapter` (`engine_id="clamav"`)

1. **Strict client.** Commands with the `z…\0` framing; `zINSTREAM\0` then
   4-byte big-endian chunk lengths and a zero terminator, sending bytes only
   from the M3 `BoundReader` (bounded chunks, cancellation and the request
   deadline between chunks). Replies: read until NUL with a hard size cap;
   accept exactly `stream: OK`, `stream: <name> FOUND`, `<text> ERROR` (and
   `INSTREAM size limit exceeded. ERROR`); a missing `stream:` prefix, EOF
   before NUL, an over-long reply, an empty reply or trailing garbage is a
   typed `ERROR` — never clean (RT-032). Socket timeout → `TIMEOUT`;
   connection refused → `UNAVAILABLE`.
2. **Readiness, as separate fields** (R11 §5): `transport_ready` (PING →
   `PONG`), `daemon_verified`, `database_loaded`/`database_verified`
   (`VERSION` parsed into engine version, daily DB version and DB date),
   `database_fresh` (DB date not older than a configurable age, default 7
   days — RT-034; the clock is injected), `reload_confirmed` (a `RELOAD`
   answered `RELOADING` is **not** activation: confirmed only when `VERSION`
   later reports the new daily version — RT-030), `configuration_acceptable`
   (injected facts, e.g. that `AlertExceedsMax` is on — RT-012). Expose a
   `generation_digest` from the active DB version + config digest (RT-033),
   never from counts.
3. **Daemon verification (R11 §9 default).** The proposed default is: verify
   the **connected socket's owner PID** against the daemon identity Sentinel
   launched (PID + creation time + image path). On Windows, look up the
   server end of our TCP connection in `GetExtendedTcpTable`
   (`TCP_TABLE_OWNER_PID_ALL`) via `ctypes`, match its PID, then compare
   creation time / image path from an injected expected identity. Make the
   verifier an injected callable so tests can fake it; when verification is
   impossible or fails, the stage status is `UNVERIFIED` and any `FOUND`
   becomes notify-only evidence (`verified=False`) — M1 policy already turns
   that into `UNACCEPTED_DETECTION`/`UNVERIFIED_CLAMD`.
4. **Evidence and coverage.** Name classification uses M1
   `policy.classify_clamav_name` (weak prefixes, `Win.Trojan.Suspect-34`,
   coverage names `Heuristics.Limits.Exceeded.*`/`Heuristics.Encrypted.*` →
   coverage debt, not malware — RT-001, RT-012, RT-028). Keep the exact raw
   name and the DB generation as provenance. Coverage: the outer byte ranges
   actually sent; `certainty="verified"` for those outer bytes **only** when
   the daemon, database and reload state are verified, otherwise
   `"declared"` (this resolves the M1 F8 note — explain it in a comment and
   adjust `policy.py` only if needed, with a test). Following R11 §9's
   default for opaque containers: when the bytes are a container type that
   Sentinel's own inventory does not cover (detect by magic: RAR, 7z, CAB,
   OLE2, PDF, MSI…; ZIP is inventoried by core), record an opaque-object
   reason so an `OK` cannot make such a file trusted clean. List the magic
   table in the code with sources.
5. **Concurrency.** A bounded pool (2–3 concurrent INSTREAMs, R11 §3);
   cancellation closes only the active socket.

## Required tests (`tests/gate_v2/`)

A fake clamd on `127.0.0.1` (ephemeral port, a thread, harmless bytes only)
driving the full matrix of R11 §7 row "Fake clamd": `OK`, `FOUND` (strong
name), `FOUND` weak (`PUA.`, `Heuristics.`, `BC.Heuristics.`,
`Win.Trojan.Suspect-34`), limit/encrypted names, `ERROR`, empty, wrong
prefix, EOF before NUL, over-long reply, garbage after NUL, timeout, refused
connection, unverified daemon with `FOUND`, `RELOADING` followed by the old
version (not confirmed) and then the new one (confirmed), stale database
date, a container-magic file with `OK` (not trusted clean). Each with the
stage status, evidence strength and the final M1 decision through the
orchestrator. Verifier tests use a fake; one Windows-only test may check that
the real TCP-table lookup finds the fake server's own PID (skip elsewhere).
If sockets are blocked in your sandbox, say so; Claude runs them.

## Running the tests

`..\sentinel-guard\.venv\Scripts\python -m pytest -q tests/gate_v2 -p no:cacheprovider`
If the sandbox refuses temp folders, report it and stop; create no folders.

## Constraints

Python 3.12+, typed, stdlib only, small modules, comments explain why, LF.
No real clamd needed or started; no network beyond 127.0.0.1 test sockets.
Stricter reading when R11 is ambiguous; list ambiguities.

## Your answer

English, concise: files and line counts, API, RT/invariant → test mapping,
changes to M1–M3 files and why, the exact command and real output, open
points for milestones 5–6.
