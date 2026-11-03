# Codex task SVC18V: verify waits for the ETW check

## Allowed paths

Changed: `agent/sentinel/service/verify.py`. New: `tests/test_svc18v.py`. Everything else is read-only;
`agent/sentinel/service/etw.py` is changed by round SVC18 at the same time. `tests/test_svc11.py` and
`tests/test_svc17.py` pin `verify._etw` strings and must keep passing unchanged.

## Why

From round SVC18 the ETW check at service start takes up to about 10 s: up to 2 s waiting for the consumer to
connect, then a fixed 7 s schedule. `verify.run` reads `status` once for the `etw` line (`check("etw", ...)`), so on
the install it can read `etw: checking` and report a SKIP that says nothing. `tools/install_service.cmd` then
restarts the service, which interrupts the check of the first start.

SVC18 adds these status fields under `observation`: `etw_flush_assist` (bool: the check passed only after an
explicit flush, and the session now flushes every second), `etw_check_phase` (`W`, `B` or `F`: the phase in which
the check passed, empty otherwise), `etw_truncated` and `etw_query_failures` (ints, reported apart from the loss).

## Build

1. `_etw_settled(client)`: request `status` every 0.5 s while `observation.etw` is `checking`, up to
   `ETW_WAIT_SECONDS = 20`, then return `_etw(status)`. Still `checking` at the deadline: SKIP with
   "ETW chưa kiểm xong sau 20 giây". Only `checking` waits: `off` and every failure state are final. Use it in
   `run()` for the `etw` check.
2. `_etw(status)`: for inputs without the new fields, the returned tuple stays exactly as today. With them: when
   on, append ", qua ở pha <phase>" if `etw_check_phase` is set, and ", cần flush mỗi giây" if `etw_flush_assist`
   is true; when off, append ", cắt ngắn <n>" and ", truy vấn hỏng <n>" for non-zero `etw_truncated` and
   `etw_query_failures`.

Tests take no real seconds (patch `time.monotonic` and `time.sleep` in `verify`). Cover: waits through `checking`
to a final state; deadline SKIP; `off` returns at once; the new texts; old inputs unchanged.
