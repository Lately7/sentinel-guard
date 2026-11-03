# Codex red team round RED19: The phased ETW start check (new code)

Read `docs/handoff/CODEX_REDTEAM_COMMON.md` (prepended) first. Output files:
`tests/codex/test_red19_etwcheck.py` and `docs/research/RED19-etwcheck.md`. Everything else is read-only.

## Scope

`agent/sentinel/service/etw.py` (Collector, EtwObserver, NativeBackend), as merged after rounds SVC18 and SVC18B, and anything they call that matters to the attack.

## Probe at least

What an ordinary process can do to the check and the session: spawn processes with the service's child pid pattern or the same image name, flood process starts during the 7 s window, exhaust the 64-entry and 256-entry buffers, make the check pass falsely or fail falsely, keep a periodic flush running forever, leak another process's command line into the `etw check:` log, or hold the service's stop past its 10 s hint. Include races between the consumer thread, the aggregator, the check thread and the service stop.

Go beyond this list where the code invites it. Report nothing you could not tie to lines.
