"""Versioned request/response frames between the service and its clients.

Clients (tray, browser native host, CLI, consent helper) are untrusted: every
frame is size-bounded and every field is checked against the operation's
schema before the core sees it (R13 §1 "IPC contract", R13b P3).
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable

PROTOCOL_VERSION = 1
MAX_FRAME = 1024 * 1024
# The rules go to the worker in one frame, and YARA Forge alone is many megabytes.
# Only that direction, from the service to a worker it started, may be this large.
MAX_RULES_FRAME = 128 * 1024 * 1024
MAX_STR = 8192
MAX_PATH = 4096
MAX_PAGE = 20_000
MAX_EVENTS = 200


class ProtocolError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        super().__init__(message or code)


# -- framing: 4-byte little-endian length + UTF-8 JSON, as native messaging


def write_frame(stream: BinaryIO, obj: dict[str, Any], *, limit: int = MAX_FRAME) -> None:
    # Escaped, not UTF-8: a lone surrogate is a legal NTFS name and has no UTF-8 form.
    data = json.dumps(obj, separators=(",", ":")).encode("ascii")
    if len(data) > limit:
        raise ProtocolError("TOO_LARGE", "response frame over the limit")
    stream.write(struct.pack("<I", len(data)) + data)
    stream.flush()


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key] = value
    return obj


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def read_frame(stream: BinaryIO, *, limit: int = MAX_FRAME) -> dict[str, Any] | None:
    """Next frame, or None at a clean end of stream. Oversized frames are not read."""
    head = _read_exact(stream, 4)
    if not head:
        return None
    if len(head) != 4:
        raise ProtocolError("BAD_FRAME", "stream ended inside a frame header")
    (n,) = struct.unpack("<I", head)
    if n > limit:
        # The connection is dropped rather than drained: a client that sends
        # oversized frames is not worth reading another megabyte from.
        raise ProtocolError("TOO_LARGE", "request frame over the limit")
    body = _read_exact(stream, n)
    if len(body) != n:
        raise ProtocolError("BAD_FRAME", "stream ended inside a frame")
    try:
        obj = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_pairs,
                         parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise ProtocolError("BAD_FRAME", "frame is not UTF-8 JSON") from e
    if not isinstance(obj, dict):
        raise ProtocolError("BAD_FRAME", "frame is not a JSON object")
    return obj


# -- field checks


def text(args: dict[str, Any], key: str, *, max_len: int = MAX_STR, required: bool = True) -> str | None:
    v = args.get(key)
    if v is None and not required:
        return None
    if not isinstance(v, str) or not v or len(v) > max_len or "\x00" in v:
        raise ProtocolError("BAD_REQUEST", f"'{key}' must be a non-empty string up to {max_len} chars")
    return v


def integer(args: dict[str, Any], key: str, lo: int, hi: int, *, default: int | None = None) -> int:
    v = args.get(key, default)
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ProtocolError("BAD_REQUEST", f"'{key}' must be an integer in [{lo}, {hi}]")
    return v


# -- operations


@dataclass(frozen=True)
class Op:
    name: str
    # "user": any authenticated local interactive caller, including the
    # browser native host and user-level malware with the same token, so
    # these operations never weaken protection. "elevated": only a
    # high-integrity administrator token (the UAC consent helper).
    level: str
    fields: frozenset[str]
    check: Callable[[dict[str, Any]], dict[str, Any]]


def _none(args: dict[str, Any]) -> dict[str, Any]:
    return {}


def _url(args: dict[str, Any]) -> dict[str, Any]:
    return {"url": text(args, "url")}


def _path_hint(args: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"path": text(args, "path", max_len=MAX_PATH)}
    url = text(args, "url", required=False)
    if url is not None:
        out["url"] = url
    if "download_id" in args:
        out["download_id"] = integer(args, "download_id", 0, 2**31 - 1)
    return out


def _path(args: dict[str, Any]) -> dict[str, Any]:
    return {"path": text(args, "path", max_len=MAX_PATH)}


def _job(args: dict[str, Any]) -> dict[str, Any]:
    return {"job_id": text(args, "job_id", max_len=64)}


PLAN_FIELDS: dict[str, frozenset[str]] = {
    "disable_protection": frozenset(),
    "trust_host": frozenset({"host"}),
    "restore_quarantine": frozenset({"quarantine_id"}),
    "delete_quarantine": frozenset({"quarantine_id"}),
    "add_exclusion": frozenset({"path", "sha256"}),
    "approve_repair": frozenset({"repair_id"}),
}
PLAN_KINDS = tuple(PLAN_FIELDS)


def _plan_request(args: dict[str, Any]) -> dict[str, Any]:
    kind = text(args, "kind", max_len=32)
    if kind not in PLAN_KINDS:
        raise ProtocolError("BAD_REQUEST", "unknown plan kind")
    params = args.get("params", {})
    if not isinstance(params, dict):
        raise ProtocolError("BAD_REQUEST", "'params' must be an object")
    if set(params) - PLAN_FIELDS[kind]:
        raise ProtocolError("BAD_REQUEST", "unknown plan parameter")
    if kind == "trust_host":
        params = {"host": text(params, "host", max_len=253)}
    elif kind in ("restore_quarantine", "delete_quarantine"):
        params = {"quarantine_id": text(params, "quarantine_id", max_len=64)}
    elif kind == "add_exclusion":
        params = {"path": text(params, "path", max_len=MAX_PATH), "sha256": text(params, "sha256", max_len=64)}
    elif kind == "approve_repair":
        params = {"repair_id": text(params, "repair_id", max_len=64)}
    else:
        params = {}
    return {"kind": kind, "params": params}


def _page(args: dict[str, Any]) -> dict[str, Any]:
    return {"offset": integer(args, "offset", 0, 10_000_000, default=0),
            "limit": integer(args, "limit", 1, MAX_PAGE, default=MAX_PAGE)}


def _events(args: dict[str, Any]) -> dict[str, Any]:
    return {"after": integer(args, "after", 0, 2**53), "limit": integer(args, "limit", 1, MAX_EVENTS, default=MAX_EVENTS)}


def _plan_ref(args: dict[str, Any]) -> dict[str, Any]:
    return {"plan_id": text(args, "plan_id", max_len=64)}


def _plan_approval(args: dict[str, Any]) -> dict[str, Any]:
    return {"plan_id": text(args, "plan_id", max_len=64), "version": integer(args, "version", 1, 2**31 - 1)}


OPS: dict[str, Op] = {op.name: op for op in (
    Op("hello", "user", frozenset(), _none),
    Op("status", "user", frozenset(), _none),
    Op("check_url", "user", frozenset({"url"}), _url),
    Op("download_hint", "user", frozenset({"path", "url", "download_id"}), _path_hint),
    Op("scan_request", "user", frozenset({"path"}), _path),
    Op("job_status", "user", frozenset({"job_id"}), _job),
    Op("cancel_job", "user", frozenset({"job_id"}), _job),
    # Only ever makes protection stronger, so it needs no confirmation.
    Op("enable_protection", "user", frozenset(), _none),
    Op("list_quarantine", "user", frozenset(), _none),
    Op("events", "user", frozenset({"after", "limit"}), _events),
    Op("allowed_hosts", "user", frozenset({"offset", "limit"}), _page),
    # Asking is harmless: a plan does nothing until an elevated caller approves it.
    Op("request_plan", "user", frozenset({"kind", "params"}), _plan_request),
    Op("get_plan", "elevated", frozenset({"plan_id"}), _plan_ref),
    Op("approve_plan", "elevated", frozenset({"plan_id", "version"}), _plan_approval),
)}


@dataclass(frozen=True)
class Request:
    id: int
    op: Op
    args: dict[str, Any]


def parse_request(frame: dict[str, Any]) -> Request:
    if type(frame.get("v")) is not int or frame["v"] != PROTOCOL_VERSION:
        raise ProtocolError("BAD_VERSION", "unsupported protocol version")
    if set(frame) - {"v", "id", "op", "args"}:
        raise ProtocolError("BAD_REQUEST", "unknown request field")
    rid = frame.get("id")
    if not isinstance(rid, int) or isinstance(rid, bool) or not 0 <= rid < 2**53:
        raise ProtocolError("BAD_REQUEST", "'id' must be a non-negative integer")
    name = frame.get("op")
    op = OPS.get(name) if isinstance(name, str) else None
    if op is None:
        raise ProtocolError("UNKNOWN_OP", "unknown operation")
    args = frame.get("args", {})
    if not isinstance(args, dict):
        raise ProtocolError("BAD_REQUEST", "'args' must be an object")
    # Unknown fields are refused, so a client cannot smuggle options that a
    # later version might start honouring.
    extra = set(args) - op.fields
    if extra:
        raise ProtocolError("BAD_REQUEST", "unknown argument")
    return Request(rid, op, op.check(args))


def ok(rid: int, result: dict[str, Any]) -> dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "id": rid, "ok": True, "result": result}


def error(rid: int | None, code: str, message: str = "") -> dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "id": rid, "ok": False, "error": {"code": code, "message": message[:300]}}
