# Codex task SVC11B: second round on ETW

Your uncommitted change from SVC11 is in this worktree; continue from it. Same allowed paths, and `service/procwatch.py`
is read-only but may be imported. Findings from review. Nothing here has run on a real session, and a real run costs
the owner a UAC click, so a wrong guess has to fail visibly and tell us why.

**1. The process event has no full path.** `_image_name` searches the payload for `C:\` or `\Device\`. Per the
documented `Process_TypeGroup1` class, the payload after the fixed fields holds a variable-length user SID, then
`ImageFileName`, a short ANSI name such as `python.exe`, then `CommandLine` in UTF-16. So on a real session the regex
finds nothing, `process_ok` stays false, and ETW is off for good with `schema_process_missing`. Check Microsoft's
documentation for the V3 and V4 layouts on 64-bit, parse the fields properly, including the SID's real length, and
carry the short name and the command line in `ParsedEvent`. The command line may contain anything: bound it, and it
never reaches `status` or any log, except as finding 5 says.

**2. Get the path from the pid.** On `process_start` resolve the image at once with `procwatch.windows_resolve`, the
sampler's own function, and offer that path. The sampler's `ProcessKey` needs a creation time: use what it needs.
Paths reaching `_offer` are drive-letter paths, as everywhere else in the product; nothing with `\\?\GLOBALROOT` or
`\Device\` may reach `wanted`, `is_protected` or an action, since those compare drive-letter paths. If the process has
gone already, count it in `etw_exits_before_resolution`. The live check compares the short name and pid with the child.

**3. Do not hold up the start of the service.** `MachineObservers.start` runs the check synchronously, adding 5 to 8 s
before `RUNNING`. Run it on a daemon thread. `stop` during a check must not leave a session behind and must not end up
reading `on`.

**4. One dropped event must not switch ETW off.** `if reason or collector.counters.gap` fails the check on any queue drop,
and a busy machine drops file events. Only a gap in what the check itself needed fails it.

**5. A failed check must say what it saw.** On a failure, log at WARNING under the prefix `etw check:` the event counts by
provider and opcode, and the first 160 bytes in hex of up to 2 process events and 2 file events belonging to the check's
own child and own file, so the real layout can be read from one run. Only those events: they hold nothing of the user's.
One line each, under 12 lines in all. `tools/install_service.cmd` prints the tail of `service.log`.

**6. File events must not cost a core.** Each file read or write on the whole machine calls back into Python. On a busy
machine that can take a core and starve the service. Add a rate guard: count callbacks, and when they exceed about
20,000 per second for 15 s, disable the IO provider with `EnableTraceEx2`, keeping process events, record it as a gap,
report `etw_file_events: guarded`, and try again after 10 minutes, doubling up to an hour. With no `on_file_event`
set, do not enable the IO keywords after the check at all. Report events per second and the time spent in callbacks
in `status`, so the cost is measured on the owner's machine and not guessed.

Each finding needs a test that fails before it. Canned payload bytes built from the documented layout are fine, and say
that they are built from the documentation, not captured.
