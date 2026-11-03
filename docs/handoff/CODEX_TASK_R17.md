# Codex task R17 (research, read-only): a file event source for ransomware scoring

## Allowed paths

New: `docs/research/R17-file-source.md`. Everything else is read-only; change no code. Web reading is allowed;
download nothing.

## Question

Shadow ransomware scoring (`agent/sentinel/service/shadow.py`) needs file read, write, rename and delete events
attributed to a process. ETW FileIo through the system logger cannot be used: on the owner's machine a Python
consumer lost 373,432 events in a few seconds, so the service enables process events only and scoring has no
source. Constraints set by the owner: user mode only, a LocalSystem service in Python with ctypes, no kernel
driver, no new dependency, nothing installed (no Sysmon).

Answer, with sources (Microsoft documentation first, then the source of real consumers):

1. `Microsoft-Windows-Kernel-File`: its keywords and event ids for create, read, write, rename, delete and
   set-information with file names; which fields it carries (process id, file object, path); whether a real-time
   session can filter it in the kernel before delivery (`EVENT_FILTER_DESCRIPTOR`: event id, PID, executable
   name, payload filters via `TdhCreatePayloadFilter`, path filters), and which of those filters apply to a
   manifest provider; the expected volume on a desktop with and without such filters.
2. Whether any filter can scope the system logger's FileIo or the new system IO provider (we believe not; confirm
   or refute).
3. The USN journal as a source: what it gives (reasons, file reference, no pid), latency, and how scoring could
   use it without attribution, or with attribution joined from process events.
4. Other user-mode sources: Defender Controlled Folder Access events, the Windows Search indexer, others you find.
5. A recommendation for this project, with the volume numbers that justify it, and what to measure on the owner's
   machine first.

Ground the answer in `shadow.py`, `burst.py`, `observers.py`, `usn.py` and `etw.py`. Mark every inference as one.
