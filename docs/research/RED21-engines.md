# RED21 — Scan engines and untrusted output

## High — Defender's name cap can discard the only conclusive detection

- **Attacker model:** A downloaded file that triggers more than 16 Defender detections, with weak PUA names printed before a malware name. The test substitutes only MpCmdRun's stdout and exit code; whether a real Defender version emits this ordering is inferred.
- **Steps:** Return code 2 and 17 valid `Threat :` lines, the first 16 `PUA:Win32/...` and the last `Virus:Win32/NamedMalware`. The adapter keeps `names[:16]` and sets `THREAT_NAME_LIMIT`.
- **Effect:** The conclusive malware name is lost. The decision is suspicious rather than malicious, so automatic quarantine is not selected for the Defender hit.
- **Lines:** `agent/sentinel/gate_v2/defender.py:294-307` collects names and truncates in output order; `agent/sentinel/gate_v2/policy.py:54-60` makes PUA supporting and malware conclusive; `agent/sentinel/gate_v2/policy.py:188-199` uses those strengths to decide the label.
- **Proposed fix:** Classify all bounded names before selection and reserve evidence slots for conclusive hits. Keep the coverage limit when any names are omitted; if all names cannot be safely classified, return an incomplete result rather than silently selecting weak names.
- **Test:** `test_defender_name_cap_keeps_later_conclusive_hit` in `tests/codex/test_red21_engines.py`. **Proven:** the parser and decision lose the later conclusive line. **Inferred:** a real file and Defender release can produce that particular 17-line ordering.

## High — A late content-engine result can clear a file after its deadline

- **Attacker model:** A downloaded file that makes YARA-X spend time scanning. The test uses a synthetic YARA scanner and clock, with no executable or malware sample.
- **Steps:** Start the YARA stage before the request deadline, then let its `scan()` return after the deadline with no matches. The adapter returns `COMPLETED/CLEAN`; the orchestrator notices the deadline but only sets `stop` for subsequent stages.
- **Effect:** If YARA is the final required stage, the file is reported clean even though the scan deadline expired. The same acceptance path applies to a late rule result. In the restricted service worker, the parent deadline can kill the worker first; the direct/tray scan path remains affected.
- **Lines:** `agent/sentinel/gate_v2/rules.py:260-318` has no deadline check around the outer YARA scan and returns completed; `agent/sentinel/gate_v2/orchestrator.py:189-229` checks the deadline after the adapter without changing its result; `agent/sentinel/gate_v2/policy.py:200-210` accepts the completed result as clean.
- **Proposed fix:** When a stage returns after the request deadline, replace its completed negative result with a typed timeout before policy evaluation. Preserve a conclusive positive finding only under an explicit policy rule. Also check the deadline between YARA scans of archive members.
- **Test:** `test_yara_late_result_cannot_clear_file` in `tests/codex/test_red21_engines.py`. **Proven:** the orchestrator accepts a late clean YARA result. **Inferred:** a particular downloaded file can make the real YARA library consume the required time.

## Other probes

No additional finding was established for these cases. Gate v2 Defender accepts named threats only with code 2 and validated ASCII names (`agent/sentinel/gate_v2/defender.py:24-26,289-315`); unexpected exit codes and overlong, control-character, or replacement-character output become errors. Its runner bounds stdout and uses a job with a deadline (`agent/sentinel/gate_v2/defender.py:139-204`). A forged `Threat :` line inside a printed filename would be ambiguous to the line parser, but I could not establish a Windows filename and MpCmdRun output path that produces it. Gate v2 clamd bounds and strictly decodes NUL-terminated replies, then requires the exact `stream:` frame (`agent/sentinel/gate_v2/clamd.py:90-153`). The older, permissive parsers in `agent/sentinel/engine/defender.py:123-133` and `agent/sentinel/engine/clamav.py:255-275` are not used for the scanner verdict; `agent/sentinel/engine/scanner.py:70-72,105-111` routes to the Gate v2 adapters. Parsed names reach findings through `agent/sentinel/gate_v2/legacy.py:121-163`, so the dropped Defender name is also absent from the UI finding.
