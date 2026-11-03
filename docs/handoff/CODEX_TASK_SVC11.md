# Codex task SVC11: ETW in the service, beside the sampler

The owner chose to stay in user mode as LocalSystem, with no driver, and to use ETW. `service/etw.py` has a
collector that nothing starts, and it refuses to run with `SCHEMA_UNVERIFIED`. Read
`docs/research/R14-etw-ransomware-detection.md` and all of `service/etw.py` first.

## Allowed paths

Changed: `agent/sentinel/service/etw.py`, `agent/sentinel/service/verify.py`, `agent/sentinel/service/installer.py`
(required privileges only), `agent/sentinel/service/backend.py` (`_machine_observers` and `status` only).
New: `tests/test_svc11.py`. `tests/test_service_installer.py` may change only where a privilege list is pinned.
Everything else is read-only.

## Build

1. **Which privilege the session needs.** The service token holds only SeImpersonatePrivilege and
   SeIncreaseQuotaPrivilege, because `installer.service_config` sets required privileges. Work out from R14 and
   Microsoft's documentation what these system providers and this logger mode need, and whether it must be enabled
   at run time. If one is needed, add it to `service_config` with the reason in a comment, add it to `configure`'s
   read-back check, and enable it only for the session start. Say which source you relied on.
2. **The schema is checked at run time, not assumed.** Replace the fixed refusal with a bounded self-check at
   start: the session runs, events are parsed, and the parsed fields are compared with what the process list and
   the file system really show, for example a process the check itself starts as a harmless child, or the
   service's own known file. If the check does not pass, ETW stays off, with the reason recorded. Nothing depends
   on it being on.
3. **Beside the sampler, never instead of it.** `ProcessWatcher` keeps running. A start from ETW only adds a
   process hint through the same `_offer` path, so a short-lived process gets its image scanned, resolved from the
   event's image name. The file events feed nothing yet: expose them through a callback that another round will
   use, `on_file_event: Callable[[ParsedEvent], None] | None`.
4. **No action comes from ETW.** It offers work to the scan path, which already decides. Bounded queues keep
   their limits, and losing events counts as a gap, reported, never as nothing happened.
5. **`status` and `verify`.** `status["observation"]` gains `etw`: `off`, `checking`, `on` or a failure reason, plus
   events parsed and lost. `verify` gains an `etw` line: PASS when on, SKIP with the reason when off, since the
   product works without it. Stop must end the session within the existing stop bound, and a session left by a
   crashed service must be recovered at the next start, not refused with `ERROR_ALREADY_EXISTS`.
