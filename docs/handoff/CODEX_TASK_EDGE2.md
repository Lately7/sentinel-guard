# Codex task EDGE2: devilish edge cases for the service request path

## Allowed paths

New: `tests/codex/test_service_core_edges.py`. Everything else is read-only; change no product code.

## Goal

The owner asked for "edge case quỷ". Read `agent/sentinel/service/core.py`, `protocol.py`, `bridge.py`,
`backend.py` and the existing service tests, then write tests that try to break the request path in process
(never through the installed service; `tests/conftest.py` blocks its pipe). Probe, among others:

* Frames: exactly `MAX_FRAME`, one byte over, zero length, a length prefix with no body, a body cut mid-UTF-8,
  invalid UTF-8, JSON with duplicate keys, deeply nested JSON, huge integers, NaN and Infinity, a top-level
  array, extra unknown fields, wrong types for every field.
* Plans and approvals: approve twice, approve after `PLAN_TTL_SECONDS` exactly and just before it, claim on one
  connection and approve on another, approve a plan of another requester, an unknown or forged plan id, a plan
  kind not in `PLAN_KINDS`, a valid kind with arguments of the wrong shape.
* Paths in requests: `\\?\` and `\\.\` prefixes, UNC, device paths, alternate data streams (`file:stream`),
  trailing dots and spaces, 8.3 short names, mixed case, `..` segments, very long paths, a junction inside
  `tmp_path` pointing elsewhere (create it with `_winapi.CreateJunction`; skip if that fails).

For each test, state in a one-line comment what the correct behaviour is and why. A test that you believe exposes
a real bug stays a plain failing test with the comment `# expected to fail: <why>`; never mark it xfail or skip
it. Use only harmless inputs (the marker rule, EICAR in memory). Report the tests you expect to fail, with the
reason, in your final answer.
