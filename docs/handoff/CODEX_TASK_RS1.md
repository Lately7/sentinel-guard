# Codex task RS1: a restore through the service says whether the download mark survived

## Allowed paths

Changed, only where the restore result is produced or shown: `agent/sentinel/service/backend.py` (the
`restore_quarantine` branch of the approved-plan action, around `return {"restored": ...}`),
`agent/sentinel/bridge.py`, `agent/sentinel/tray.py`, `agent/sentinel/__main__.py` (the `quarantine restore`
output). New: `tests/test_rs1.py`. Everything else is read-only.

## Why

`quarantine.restore` returns a `RestoredPath` whose `zone_identifier_preserved` is True (the file's download
mark, Zone.Identifier, came back with it), False (it had one and lost it), or None (it had none, or it is not
known). Windows warns before opening a downloaded file only when that mark is present. A restore through the
service replies with `restored` and `autostart_restored` only, so the tray and the CLI cannot tell the user that
a restored download lost its mark. Read how the local (no-service) restore path reports it first, and keep both
paths consistent.

## Build

1. The service reply adds `zone_identifier_preserved` (true, false or null) from the `RestoredPath`.
2. The bridge passes it on; old services that do not send it read as null.
3. Tray and CLI: when it is false, say so in Vietnamese, for example "Đã khôi phục, nhưng không giữ được dấu tải
   từ Internet: Windows sẽ không cảnh báo khi mở tệp này." Nothing extra when true or null.

Tests: the reply carries the field for each of the three values; a reply without it reads as null; the tray and
CLI text appears only for false. Use the existing fakes for the service and quarantine; touch no real file outside
`tmp_path`.
