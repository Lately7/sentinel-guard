# Codex fix round FIX1: strict request frames (EDGE2)

Worktree: the EDGE2 worktree; the tests are `tests/codex/test_service_core_edges.py`.

## Allowed paths

`agent/sentinel/service/protocol.py`, `agent/sentinel/service/client.py`, `tests/codex/test_service_core_edges.py`.

## Findings (all confirmed as hardening by triage and skeptic)

* `test_partial_length_prefix_is_not_clean_eof`: a stream that ends inside the 4-byte header reads as a clean end.
  Make `_read_exact` return what it read; `read_frame` returns None only for zero bytes and raises BAD_FRAME for
  1-3. Wrap `ProtocolError` in `client.py` where it reads replies so callers still get `ServiceUnavailable`
  (bridge `_call` catches only that).
* `test_duplicate_json_keys_are_rejected`: reject duplicate keys with an `object_pairs_hook` (BAD_FRAME).
* `test_nonfinite_json_numbers_are_rejected`: reject NaN and Infinity with `parse_constant` (BAD_FRAME). Do not
  set `allow_nan=False` on writes unless you prove no reply can carry a float NaN.
* `test_version_must_be_an_integer_not_an_equal_value`: `v` must be an `int`, not a bool or float.
* `test_unknown_top_level_field_is_refused`: only `v`, `id`, `op`, `args` at top level.
* `test_extra_nested_plan_parameter_is_refused`: a table of allowed parameter keys per plan kind; read how
  `request_plan` builds params today and keep every kind the product sends working.
* `test_deeply_nested_json_is_a_typed_frame_error` is a **test bug**: depth 1500 parses fine on Python 3.15 and
  `RecursionError` is already BAD_FRAME. Use a depth that cannot parse within `MAX_FRAME` and assert BAD_FRAME.

The worker's 128 MiB rules frame comes from the trusted service; the stricter parsing must not reject it.
