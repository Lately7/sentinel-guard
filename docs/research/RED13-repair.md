# RED13 — repair and persistence handling

These tests use the temporary `SENTINEL_HOME`, an in-memory registry, and harmless files. They do not call Windows registry APIs or an installed service. The tests were read against the code; pytest was not run in this sandbox.

## High — repair deletes a Run value before saving undo

- **Attacker model:** A full disk or service crash at the worst moment. A medium-integrity user can supply the Run entry being repaired.
- **Steps:** Repair quarantines the file, deletes the matching Run value, then `add_repair_undo` fails. The test injects a SQLite disk-full error.
- **Effect:** The startup value is gone, with no undo record. Restore cannot put it back. A crash in the same gap has the same ordering problem.
- **Lines:** `agent/sentinel/service/repair.py:299-303`; `agent/sentinel/db.py:651-653`.
- **Fix:** Persist a recoverable intent before deleting the value, flush it, then mark the removal complete. Reconcile incomplete intents after restart and preserve the original value if journaling fails.
- **Evidence:** `test_journal_failure_does_not_lose_run_value` proves the disk-full path with injected failure; the power-loss variant is inferred from operation order.

## High — restore can persist a different file at the old name

- **Attacker model:** A medium-integrity user can create a file at the original user-writable path while the quarantined file is absent.
- **Steps:** Before approval, occupy the original filename. Restore chooses a ` (restored)` filename. The backend then calls undo with only the quarantine ID, so undo writes the saved command pointing to the occupied original name.
- **Effect:** The approval restores one file but re-enables startup of another file the user did not choose. The plan still describes the original path.
- **Lines:** `agent/sentinel/quarantine.py:281-288,291-298,319-320`; `agent/sentinel/service/backend.py:600-608,637-644`; `agent/sentinel/service/repair.py:317-330`.
- **Fix:** Carry the actual restored target into undo; rebind commands only when the target can be changed safely, otherwise leave the Run value disabled and explain it in the result. Recheck the restore destination before approval or show a fresh plan when it changes.
- **Evidence:** `test_renamed_restore_does_not_persist_occupant` proves the backend-to-undo path with a simulated restore result. Actual filename collision behavior follows the cited quarantine lines.

## Medium — changed registry type is deleted without approval

- **Attacker model:** A medium-integrity user changes their own Run value between plan and execution.
- **Steps:** Keep the text identical, change `REG_SZ` to `REG_EXPAND_SZ`, then approve repair.
- **Effect:** `remove_value` deletes a value whose type was not measured in the plan; the two types have different expansion behavior.
- **Lines:** `agent/sentinel/service/repair.py:73-79,147-153,254-266`.
- **Fix:** Compare both `data` and `kind` immediately before deletion, and leave the value in place if either differs.
- **Evidence:** `test_changed_run_type_is_not_removed` proves this in process.

## Medium — undo overwrites a later user change

- **Attacker model:** A medium-integrity user recreates or changes their Run value between repair and restore.
- **Steps:** Repair removes the old value; the user writes a new command under the same name; undo unconditionally calls `SetValueEx`.
- **Effect:** Restore silently replaces the user's newer startup choice with the old command.
- **Lines:** `agent/sentinel/service/repair.py:324-330`.
- **Fix:** Read the current value first. Restore only when the name is still absent, or present an explicit conflict for separate approval.
- **Evidence:** `test_undo_preserves_replaced_run_value` proves this in process.

## Medium — failed undo consumes the journal

- **Attacker model:** A temporarily unavailable registry key during restore, including a key the medium-integrity user can change or remove.
- **Steps:** Make `SetValueEx` raise `OSError`; undo catches it and then clears every saved row for that quarantine ID.
- **Effect:** The startup value cannot be retried even after the key becomes available.
- **Lines:** `agent/sentinel/service/repair.py:324-334`; `agent/sentinel/db.py:655-659`.
- **Fix:** Delete only rows successfully restored, retaining failed rows for retry and reporting their count.
- **Evidence:** `test_failed_undo_keeps_its_journal` proves this in process.

## Medium — an unpaired surrogate name loses its undo record

- **Attacker model:** A medium-integrity user creates a Run value with a malformed UTF-16 name in their own hive.
- **Steps:** The service sees the name, removes the value, then passes the name to SQLite. SQLite's UTF-8 encoding raises `UnicodeEncodeError`.
- **Effect:** The value is removed with no saved undo, and repair exits with an uncaught exception.
- **Lines:** `agent/sentinel/service/repair.py:147-153,299-303`; `agent/sentinel/db.py:72-80,651-653`.
- **Fix:** Use a reversible encoding for registry names and data that SQLite can store, and commit the undo intent before deletion. Handle encoding errors without losing the original value.
- **Evidence:** `test_unpaired_surrogate_run_name_retains_undo` proves the Python/SQLite failure with an in-memory registry. Acceptance of that name by the Windows registry is inferred from its UTF-16 storage model.

### Other probes

Scheduled tasks and WMI consumers are listed but intentionally left in place (`repair.py:159-178,193-198,297-298`). I found no repair path that modifies tasks or services. Run enumeration and the resulting `Repair.autostart` tuple have no explicit entry cap (`repair.py:138-156,177-178`); I did not find a concrete wrong action or service hang to report from a large finite list. The existing prompt sanitization covers control and direction characters (`repair.py:40-56`).
