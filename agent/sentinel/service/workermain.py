"""Entry point of the low-privilege scan worker (A2).

Runs inside the restricted, low-integrity, jobbed process from worker.py.
Reads frames from stdin, writes frames to stdout. It never opens a path: the
parent opens the file deny-write and duplicates a read-only handle into this
process; the worker parses those bytes with the Gate v2 adapters and returns
EngineResult dictionaries, which the parent re-validates as untrusted data.
"""

from __future__ import annotations

import base64
import os
import sys
from typing import Any

from ..gate_v2.analyzers.lnk import LnkAdapter
from ..gate_v2.analyzers.signer import SignerAdapter
from ..gate_v2.content import BoundReader, ContentError
from ..gate_v2.contract import ContractError, FileIdentity, ScanRequest
from ..gate_v2.core import CoreAdapter
from ..gate_v2.rules import JsonRulesAdapter, YaraXAdapter
from .protocol import ProtocolError, read_frame, write_frame

# MotW is not here: it reads a stream by name, and this process never gets one.
ENGINES = ("core", "json_rules", "yara_x", "lnk", "signer")


class _NeverCancel:
    # Cancellation is the parent killing this process (Job Object), so the
    # worker itself never needs a token.
    def cancelled(self) -> bool:
        return False


def _reply(out: Any, rid: Any, *, result: dict[str, Any] | None = None, code: str | None = None) -> None:
    frame: dict[str, Any] = {"id": rid, "ok": code is None}
    if code is None:
        frame["result"] = result or {}
    else:
        frame["error"] = {"code": code}
    write_frame(out, frame)


class Worker:
    def __init__(self) -> None:
        self.adapters: dict[str, Any] = {}

    def init(self, args: dict[str, Any]) -> dict[str, Any]:
        packs = tuple((str(n), base64.b64decode(b), bool(u)) for n, b, u in args.get("json_packs", []))
        sources = tuple((str(ns), str(n), str(s)) for ns, n, s in args.get("yara_sources", []))
        self.adapters = {"core": CoreAdapter(), "json_rules": JsonRulesAdapter(packs),
                         "lnk": LnkAdapter(), "signer": SignerAdapter(),
                         # Also with no rules yet: the gate requires the stage either
                         # way, and a fresh install would call every file unknown.
                         "yara_x": YaraXAdapter(sources)}
        return {"engines": sorted(self.adapters),
                "json_rules_digest": self.adapters["json_rules"].ruleset_digest}

    def scan(self, args: dict[str, Any]) -> dict[str, Any]:
        adapter = self.adapters.get(args.get("engine"))
        if adapter is None:
            raise ProtocolError("UNKNOWN_ENGINE")
        if args["engine"] == "core":
            # The hash lists live with the service; this process has no database.
            feed = args.get("known_bad")
            adapter = CoreAdapter(lambda digest: feed)
        request = ScanRequest.from_dict(args["request"])
        identity = FileIdentity.from_dict(args["identity"])
        handle = args.get("handle")
        if handle is not None:
            import msvcrt

            fd = msvcrt.open_osfhandle(int(handle), os.O_RDONLY)
            with os.fdopen(fd, "rb", buffering=0) as stream:
                reader = BoundReader.from_stream(stream, identity)
                result = adapter.scan_bound(request, identity, _NeverCancel(), reader)
        else:
            if request.data is None:
                raise ProtocolError("NO_CONTENT")
            reader = BoundReader.from_bytes(request.data, identity)
            result = adapter.scan_bound(request, identity, _NeverCancel(), reader)
        return {"engine_result": result.to_dict()}


def main() -> int:
    inp, out = sys.stdin.buffer, sys.stdout.buffer
    worker = Worker()
    while True:
        try:
            frame = read_frame(inp)
        except ProtocolError as e:
            _reply(out, None, code=e.code)
            return 2
        if frame is None:
            return 0
        rid, op, args = frame.get("id"), frame.get("op"), frame.get("args") or {}
        try:
            if op == "init":
                _reply(out, rid, result=worker.init(args))
            elif op == "scan":
                _reply(out, rid, result=worker.scan(args))
            else:
                _reply(out, rid, code="UNKNOWN_OP")
        except (ProtocolError, ContentError, ContractError) as e:
            _reply(out, rid, code=getattr(e, "code", "BAD_REQUEST"))
        except Exception:
            # No traceback text crosses the boundary: it can carry file
            # content or paths. The parent reports a typed worker error.
            _reply(out, rid, code="WORKER_ERROR")


if __name__ == "__main__":
    sys.exit(main())
