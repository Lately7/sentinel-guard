# R12d — Wazuh v4.14.9 agent, FIM, rootcheck and rules, read from source

The current directory is a sparse checkout of Wazuh at tag `v4.14.9`
containing `src/syscheckd`, `src/rootcheck`, `src/wazuh_modules`,
`src/analysisd`, `src/client-agent`, `src/os_execd`, `src/active-response`,
`src/shared`, `src/headers`, `src/os_regex`, `ruleset/`, `etc/`,
`architecture/`. Other parts are absent on purpose.

## Questions

1. **Architecture.** From `architecture/` and the code: agent processes,
   manager processes, how events flow agent → manager → analysisd → alerts,
   and which parts run on a Windows agent.
2. **File integrity monitoring (syscheckd) on Windows.** Real-time mode
   (which API: `ReadDirectoryChangesW`?), who-data (audit/ETW, needs admin?),
   scheduled scans, the FIM database, hashing, debouncing/queueing, how it
   bounds memory and event rate, what happens when events overflow or a file
   is locked, registry monitoring. `path:line` for each. Compare point by
   point with Sentinel's `agent/sentinel/watcher.py` (read it in the
   Sentinel repository), and list concrete improvements for RT-016 (locked
   files), RT-017 (unbounded debounce) and RT-018 (stop vs in-flight action).
3. **Rootcheck and syscollector.** What rootcheck checks on Windows, how
   policy files are written, what syscollector inventories (processes,
   programs, hotfixes, ports) and with which APIs.
4. **Rules and decoders.** analysisd rule engine: decoder → rule matching,
   levels, frequency/timeframe correlation (`if_matched_sid`, `same_field`),
   overwrite/exceptions, and how false positives are tuned. Pick the
   Windows/FIM/malware-related rules in `ruleset/` and explain 10 of them.
5. **Active response.** How a rule triggers an action on the agent, what
   protects against abuse, and the lesson for Sentinel's separation of
   detection policy and action policy.

## Deliverable

Sections 1–5 with tables, then "Implications for Gate v2 and real-time
protection": the event-correlation and FIM patterns Sentinel should adopt in
user mode, with bounded designs and harmless tests, and what it cannot copy
without admin rights.
