"""In-process adversarial boundaries for the service request path."""

from __future__ import annotations

import hashlib
import io
import os
import struct
from pathlib import Path
from typing import Any

import pytest

from sentinel.gate_v2.identity import measure
from sentinel.service.authz import Caller
from sentinel.service.client import ServiceClient, ServiceUnavailable
from sentinel.service.core import PLAN_TTL_SECONDS, ServiceCore, local_path
from sentinel.service.protocol import MAX_FRAME, MAX_PATH, ProtocolError, parse_request, read_frame


USER = Caller("S-1-5-21-edge-1001", 1, "medium", False)
HELPER = Caller(USER.sid, USER.session_id, "high", True)


class Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        return self.t


class FakeBackend:
    def __init__(self) -> None:
        self.readable: set[str] = set()
        self.submitted: list[tuple[str, str, str | None]] = []
        self.executed: list[tuple[str, dict[str, Any]]] = []

    def can_read(self, caller: Caller, path: str) -> bool:
        return path in self.readable

    def submit_scan(self, path: str, *, reason: str, url: str | None, caller: Caller) -> str:
        self.submitted.append((path, reason, url))
        return f"job{len(self.submitted)}"

    def describe_plan(self, kind: str, params: dict[str, Any]) -> str | None:
        return "Xác nhận hành động" if kind == "disable_protection" else None

    def execute_plan(self, kind: str, params: dict[str, Any]) -> dict[str, Any]:
        self.executed.append((kind, params))
        return {"done": True}


def _frame(body: bytes, *, length: int | None = None) -> io.BytesIO:
    return io.BytesIO(struct.pack("<I", len(body) if length is None else length) + body)


def _request(op: str, **args: Any) -> dict[str, Any]:
    return {"v": 1, "id": 1, "op": op, "args": args}


def _code(reply: dict[str, Any]) -> str | None:
    return None if reply["ok"] else reply["error"]["code"]


def _plan(core: ServiceCore) -> str:
    reply = core.handle(USER, _request("request_plan", kind="disable_protection", params={}))
    assert reply["ok"]
    return reply["result"]["plan_id"]


def _claim(core: ServiceCore, plan_id: str, *, connection: str = "first") -> dict[str, Any]:
    return core.handle(HELPER, _request("get_plan", plan_id=plan_id), connection_id=connection)


def _approve(core: ServiceCore, plan_id: str, *, connection: str = "first") -> dict[str, Any]:
    return core.handle(HELPER, _request("approve_plan", plan_id=plan_id, version=1), connection_id=connection)


def test_frame_exactly_at_limit_is_read() -> None:
    # A valid frame at the inclusive byte limit must remain readable.
    prefix, suffix = b'{"pad":"', b'"}'
    body = prefix + b"a" * (MAX_FRAME - len(prefix) - len(suffix)) + suffix
    assert len(body) == MAX_FRAME
    assert len(read_frame(_frame(body))["pad"]) == MAX_FRAME - len(prefix) - len(suffix)


def test_frame_one_byte_over_limit_is_rejected_before_body_read() -> None:
    # An oversized declared length must be refused without waiting for its body.
    with pytest.raises(ProtocolError) as caught:
        read_frame(_frame(b"", length=MAX_FRAME + 1))
    assert caught.value.code == "TOO_LARGE"


@pytest.mark.parametrize("body,length", [
    (b"", 0),
    (b"", 10),
    (b'{"x":"\xc3', None),
    (b'{"x":"\xff"}', None),
    (b"[]", None),
])
def test_empty_truncated_invalid_and_array_frames_are_bad(body: bytes, length: int | None) -> None:
    # Empty, cut, non-UTF-8, and non-object frames cannot become requests.
    with pytest.raises(ProtocolError) as caught:
        read_frame(_frame(body, length=length))
    assert caught.value.code == "BAD_FRAME"


def test_partial_length_prefix_is_not_clean_eof() -> None:
    # A cut prefix must not hide a broken frame as clean EOF.
    with pytest.raises(ProtocolError) as caught:
        read_frame(io.BytesIO(b"\x05\x00"))
    assert caught.value.code == "BAD_FRAME"


def test_client_wraps_malformed_reply_as_service_unavailable() -> None:
    class BrokenReply:
        def __init__(self) -> None:
            self.incoming = io.BytesIO(b"\x05\x00")
            self.closed = False

        def read(self, n: int) -> bytes:
            return self.incoming.read(n)

        def write(self, data: bytes) -> int:
            return len(data)

        def flush(self) -> None:
            pass

        def close(self) -> None:
            self.closed = True

    stream = BrokenReply()
    client = ServiceClient()
    client._conn = stream
    with pytest.raises(ServiceUnavailable) as caught:
        client.request("hello")
    assert caught.value.code == "SERVICE_UNAVAILABLE"
    assert stream.closed and client._conn is None


def test_duplicate_json_keys_are_rejected() -> None:
    # A duplicate operation must not silently replace the earlier value.
    body = b'{"v":1,"id":1,"op":"hello","op":"enable_protection"}'
    with pytest.raises(ProtocolError) as caught:
        read_frame(_frame(body))
    assert caught.value.code == "BAD_FRAME"


@pytest.mark.parametrize("number", [b"NaN", b"Infinity", b"-Infinity"])
def test_nonfinite_json_numbers_are_rejected(number: bytes) -> None:
    # Non-JSON number tokens must not enter request frames.
    with pytest.raises(ProtocolError) as caught:
        read_frame(_frame(b'{"v":1,"id":1,"op":"hello","extra":' + number + b"}"))
    assert caught.value.code == "BAD_FRAME"


def test_deeply_nested_json_is_a_typed_frame_error() -> None:
    # Excessive nesting must become a framing error rather than escaping recursion failure.
    prefix, suffix = b'{"extra":', b"}"
    depth = (MAX_FRAME - len(prefix) - len(suffix) - 1) // 2
    body = prefix + b"[" * depth + b"0" + b"]" * depth + suffix
    assert len(body) <= MAX_FRAME
    with pytest.raises(ProtocolError) as caught:
        read_frame(_frame(body))
    assert caught.value.code == "BAD_FRAME"


def test_huge_integer_id_is_refused_without_backend_work() -> None:
    # A syntactically valid huge integer must fail the bounded request ID check.
    body = b'{"v":1,"id":' + b"9" * 300 + b',"op":"hello"}'
    backend = FakeBackend()
    reply = ServiceCore(backend).handle(USER, read_frame(_frame(body)))
    assert _code(reply) == "BAD_REQUEST"


def test_extreme_integer_json_is_a_typed_frame_error() -> None:
    # Integer tokens beyond the decoder's safety limit must become BAD_FRAME.
    body = b'{"v":1,"id":' + b"9" * 5000 + b',"op":"hello"}'
    with pytest.raises(ProtocolError) as caught:
        read_frame(_frame(body))
    assert caught.value.code == "BAD_FRAME"


@pytest.mark.parametrize("version", [True, 1.0])
def test_version_must_be_an_integer_not_an_equal_value(version: object) -> None:
    # Bool and float compare equal to 1 but are not protocol versions.
    with pytest.raises(ProtocolError) as caught:
        parse_request({"v": version, "id": 1, "op": "hello"})
    assert caught.value.code == "BAD_VERSION"


def test_unknown_top_level_field_is_refused() -> None:
    # Unrecognized frame fields must not be ignored.
    with pytest.raises(ProtocolError) as caught:
        parse_request({"v": 1, "id": 1, "op": "hello", "surprise": True})
    assert caught.value.code == "BAD_REQUEST"


@pytest.mark.parametrize("field,value,expected", [
    ("v", None, "BAD_VERSION"),
    ("id", True, "BAD_REQUEST"),
    ("id", "1", "BAD_REQUEST"),
    ("op", [], "UNKNOWN_OP"),
    ("args", [], "BAD_REQUEST"),
])
def test_envelope_field_types_are_checked(field: str, value: object, expected: str) -> None:
    # Wrong envelope types must fail before authorization or backend dispatch.
    frame: dict[str, Any] = {"v": 1, "id": 1, "op": "hello", "args": {}}
    frame[field] = value
    with pytest.raises(ProtocolError) as caught:
        parse_request(frame)
    assert caught.value.code == expected


@pytest.mark.parametrize("op,args", [
    ("hello", {"extra": True}),
    ("status", {"extra": True}),
    ("check_url", {"url": 1}),
    ("download_hint", {"path": 1}),
    ("download_hint", {"path": "C:\\a", "url": 1}),
    ("download_hint", {"path": "C:\\a", "download_id": True}),
    ("scan_request", {"path": []}),
    ("job_status", {"job_id": {}}),
    ("cancel_job", {"job_id": False}),
    ("enable_protection", {"extra": 1}),
    ("list_quarantine", {"extra": 1}),
    ("events", {"after": 1.5}),
    ("events", {"after": 0, "limit": "1"}),
    ("allowed_hosts", {"offset": True}),
    ("allowed_hosts", {"limit": None}),
    ("request_plan", {"kind": []}),
    ("request_plan", {"kind": "trust_host", "params": []}),
    ("get_plan", {"plan_id": 1}),
    ("approve_plan", {"plan_id": [], "version": 1}),
    ("approve_plan", {"plan_id": "a", "version": True}),
])
def test_every_operation_rejects_wrong_argument_types(op: str, args: dict[str, Any]) -> None:
    # Invalid field types and unknown arguments must be rejected before dispatch.
    with pytest.raises(ProtocolError) as caught:
        parse_request({"v": 1, "id": 1, "op": op, "args": args})
    assert caught.value.code == "BAD_REQUEST"


@pytest.mark.parametrize("kind,params", [
    ("trust_host", {"host": 1}),
    ("restore_quarantine", {"quarantine_id": []}),
    ("delete_quarantine", {"quarantine_id": False}),
    ("add_exclusion", {"path": 1, "sha256": "a" * 64}),
    ("add_exclusion", {"path": "C:\\a", "sha256": []}),
    ("approve_repair", {"repair_id": {}}),
])
def test_valid_plan_kinds_reject_malformed_params(kind: str, params: dict[str, Any]) -> None:
    # A recognized kind still needs its own validated parameter shape.
    with pytest.raises(ProtocolError) as caught:
        parse_request(_request("request_plan", kind=kind, params=params))
    assert caught.value.code == "BAD_REQUEST"


def test_extra_nested_plan_parameter_is_refused() -> None:
    # Unknown plan parameters must not be dropped silently.
    with pytest.raises(ProtocolError) as caught:
        parse_request(_request("request_plan", kind="trust_host", params={"host": "example.test", "extra": True}))
    assert caught.value.code == "BAD_REQUEST"


def test_unknown_plan_kind_and_unknown_argument_are_refused() -> None:
    # An unrecognized action or extra argument must never reach plan creation.
    core = ServiceCore(FakeBackend())
    assert _code(core.handle(USER, _request("request_plan", kind="format_disk", params={}))) == "BAD_REQUEST"
    assert _code(core.handle(USER, _request("request_plan", kind="disable_protection", surprise=True))) == "BAD_REQUEST"
    assert core._plans == {}


def test_plan_is_usable_just_before_ttl_and_not_at_ttl() -> None:
    # A plan expires at the exact deadline, while an earlier claimed one remains usable.
    backend, clock = FakeBackend(), Clock()
    core = ServiceCore(backend, clock=clock)
    first = _plan(core)
    assert _claim(core, first)["ok"]
    clock.t += PLAN_TTL_SECONDS - 0.001
    assert _approve(core, first)["ok"]
    second = _plan(core)
    assert _claim(core, second)["ok"]
    clock.t += PLAN_TTL_SECONDS
    assert _code(_approve(core, second)) == "NOT_FOUND"
    assert len(backend.executed) == 1


def test_replayed_approval_cannot_execute_twice() -> None:
    # A successful approval consumes the plan before any replay can act.
    backend = FakeBackend()
    core = ServiceCore(backend)
    plan_id = _plan(core)
    assert _claim(core, plan_id)["ok"]
    assert _approve(core, plan_id)["ok"]
    assert _code(_approve(core, plan_id)) == "NOT_FOUND"
    assert len(backend.executed) == 1


def test_claim_on_one_connection_cannot_be_approved_on_another() -> None:
    # A stolen plan ID on a different connection cannot inherit the displayed claim.
    backend = FakeBackend()
    core = ServiceCore(backend)
    plan_id = _plan(core)
    assert _claim(core, plan_id, connection="first")["ok"]
    assert _code(_approve(core, plan_id, connection="second")) == "PLAN_CLAIMED"
    assert backend.executed == []
    assert _approve(core, plan_id, connection="first")["ok"]


def test_other_requester_cannot_claim_or_approve_plan() -> None:
    # A different account in the same session cannot approve another user's plan.
    backend = FakeBackend()
    core = ServiceCore(backend)
    plan_id = _plan(core)
    other = Caller("S-1-5-21-other", USER.session_id, "high", True)
    assert _code(core.handle(other, _request("get_plan", plan_id=plan_id), connection_id="first")) == "REQUESTER_MISMATCH"
    assert _code(core.handle(other, _request("approve_plan", plan_id=plan_id, version=1), connection_id="first")) == "REQUESTER_MISMATCH"
    assert backend.executed == []


def test_unknown_and_forged_plan_ids_never_execute() -> None:
    # Guessing a well-shaped ID or changing one digit must find no executable plan.
    backend = FakeBackend()
    core = ServiceCore(backend)
    plan_id = _plan(core)
    forged = ("0" if plan_id[0] != "0" else "1") + plan_id[1:]
    unknown = "0" * 32 if plan_id != "0" * 32 else "1" * 32
    for candidate in (unknown, forged):
        assert _code(_claim(core, candidate)) == "NOT_FOUND"
        assert _code(_approve(core, candidate)) == "NOT_FOUND"
    assert backend.executed == []


@pytest.mark.parametrize("path", [
    "\\\\?\\C:\\ordinary.txt",
    "\\\\.\\C:\\ordinary.txt",
    "\\\\server\\share\\ordinary.txt",
    "\\Device\\HarddiskVolume1\\ordinary.txt",
    "C:\\folder\\ordinary.txt:stream",
    "C:\\folder\\ordinary.txt.",
    "C:\\folder\\ordinary.txt ",
    "C:\\folder\\..\\ordinary.txt",
    "C:\\folder\\.\\ordinary.txt",
])
@pytest.mark.parametrize("op", ["scan_request", "download_hint"])
def test_alias_and_nonlocal_paths_do_not_reach_backend(path: str, op: str) -> None:
    # Device, network, stream, and normalized aliases must fail before access checks.
    backend = FakeBackend()
    core = ServiceCore(backend)
    assert _code(core.handle(USER, _request(op, path=path))) == "BAD_PATH"
    assert backend.submitted == []


def test_path_over_protocol_limit_is_refused_before_backend() -> None:
    # Oversized path text must fail schema validation before any file access.
    backend = FakeBackend()
    core = ServiceCore(backend)
    path = "C:\\" + "a" * MAX_PATH
    assert _code(core.handle(USER, _request("scan_request", path=path))) == "BAD_REQUEST"
    assert backend.submitted == []


def test_path_at_protocol_limit_retains_its_exact_spelling() -> None:
    # The inclusive schema limit must preserve the whole accepted path for access checks.
    parts = ["a" * 200] * 21
    path = "C:\\" + "\\".join(parts)
    path = path[:MAX_PATH]
    assert len(path) == MAX_PATH and local_path(path) == path
    assert parse_request(_request("scan_request", path=path)).args["path"] == path


@pytest.mark.parametrize("path,normal", [
    ("c:\\MiXeD\\SAFE.TXT", "c:\\MiXeD\\SAFE.TXT"),
    ("C:/MiXeD/SAFE.TXT", "C:\\MiXeD\\SAFE.TXT"),
    ("C:\\PROGRA~1\\SAFE.TXT", "C:\\PROGRA~1\\SAFE.TXT"),
])
def test_plain_case_slash_and_short_name_reach_backend_unchanged(path: str, normal: str) -> None:
    # A plain local spelling may pass, but the access check and scan receive the same spelling.
    backend = FakeBackend()
    backend.readable.add(normal)
    core = ServiceCore(backend)
    assert core.handle(USER, _request("scan_request", path=path))["ok"]
    assert backend.submitted == [(normal, "on_demand", None)]


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_junction_request_keeps_the_measured_target(tmp_path: Path) -> None:
    # A junction can pass lexical checks, so measurement must identify its real target bytes.
    winapi = pytest.importorskip("_winapi")
    target = tmp_path / "target"
    target.mkdir()
    body = b"harmless service edge fixture"
    (target / "ordinary.bin").write_bytes(body)
    link = tmp_path / "alias"
    try:
        winapi.CreateJunction(str(link), str(target))
    except (OSError, AttributeError, TypeError) as exc:
        pytest.skip(f"junction unavailable: {exc}")
    path = str(link / "ordinary.bin")
    assert local_path(path) == path
    backend = FakeBackend()
    backend.readable.add(path)
    core = ServiceCore(backend)
    assert core.handle(USER, _request("scan_request", path=path))["ok"]
    assert backend.submitted == [(path, "on_demand", None)]
    found = measure(path, max_bytes=len(body))
    assert found.ok and found.identity is not None
    assert found.identity.sha256 == hashlib.sha256(body).hexdigest()
    assert os.path.samefile(found.identity.canonical_path, target / "ordinary.bin")
