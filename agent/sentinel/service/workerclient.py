"""Parent side of the low-privilege scan worker (A2).

`WorkerAdapter` plugs into the Gate v2 orchestrator like any adapter, but the
parsing runs in the restricted worker: the parent duplicates the read-only,
deny-write handle of the measured file into the worker and treats whatever
comes back as untrusted data (re-validated through the contract). A worker
that dies, hangs past the deadline, is cancelled or answers garbage yields a
typed non-clean result, and the next call starts a fresh worker.
"""

from __future__ import annotations

import base64
import ctypes
import ntpath
import os
import queue
import threading
import time
from ctypes import wintypes
from dataclasses import replace
from typing import Any

from ..gate_v2.content import BoundReader
from ..gate_v2.contract import (
    CONTRACT_VERSION, CancellationToken, ContractError, Coverage, EngineResult,
    FileIdentity, ScanError, ScanRequest, StageStatus, VerdictCode,
)
from . import worker as worker_mod
from .protocol import MAX_FRAME, ProtocolError, read_frame, write_frame

POLL_SECONDS = 0.05
START_SECONDS = 30.0

if os.name == "nt":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                     ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    DUPLICATE_SAME_ACCESS = 0x2


class WorkerFailure(Exception):
    def __init__(self, status: StageStatus, code: str) -> None:
        self.status, self.code = status, code
        super().__init__(code)


class WorkerSession:
    """One worker process; calls are serialised. Restarted after any failure."""

    def __init__(self, *, json_packs: tuple[tuple[str, bytes, bool], ...] = (),
                 yara_sources: tuple[tuple[str, str, str], ...] = (),
                 memory_limit: int = 512 * 1024 * 1024) -> None:
        self._init_args = {
            "json_packs": [[n, base64.b64encode(b).decode("ascii"), u] for n, b, u in json_packs],
            "yara_sources": [list(s) for s in yara_sources],
        }
        self._memory_limit = memory_limit
        self._lock = threading.Lock()
        self._proc: worker_mod.Worker | None = None
        self._replies: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._next_id = 0
        self.starts = 0
        self.engines: list[str] = []

    # -- lifecycle

    def _start(self, deadline_ns: int) -> None:
        self._proc = worker_mod.launch(worker_mod.bootstrap("sentinel.service.workermain"),
                                       memory_limit=self._memory_limit)
        self.starts += 1
        self._replies = queue.Queue()
        threading.Thread(target=self._pump, args=(self._proc, self._replies), daemon=True,
                         name="worker-reader").start()
        started_by = min(deadline_ns, time.monotonic_ns() + int(START_SECONDS * 1e9))
        reply = self._send("init", self._init_args, started_by, None)
        self.engines = list(reply.get("engines", []))

    @staticmethod
    def _pump(proc: worker_mod.Worker, replies: queue.Queue[dict[str, Any] | None]) -> None:
        try:
            while True:
                frame = read_frame(proc.stdout)
                replies.put(frame)
                if frame is None:
                    return
        except (ProtocolError, OSError, ValueError):
            replies.put(None)

    def _kill(self) -> None:
        if self._proc is not None:
            self._proc.kill()
            self._proc = None

    def close(self) -> None:
        with self._lock:
            self._kill()

    # -- calls

    def _send(self, op: str, args: dict[str, Any], deadline_ns: int,
              cancel: CancellationToken | None) -> dict[str, Any]:
        assert self._proc is not None
        self._next_id += 1
        rid = self._next_id
        try:
            write_frame(self._proc.stdin, {"id": rid, "op": op, "args": args})
        except (OSError, ProtocolError) as e:
            self._kill()
            raise WorkerFailure(StageStatus.ERROR, "WORKER_DIED") from e
        while True:
            if cancel is not None and cancel.cancelled():
                self._kill()  # the job kills the worker mid-parse
                raise WorkerFailure(StageStatus.CANCELLED, "CANCELLED")
            remaining = (deadline_ns - time.monotonic_ns()) / 1e9
            if remaining <= 0:
                self._kill()
                raise WorkerFailure(StageStatus.TIMEOUT, "WORKER_TIMEOUT")
            try:
                frame = self._replies.get(timeout=min(POLL_SECONDS, remaining))
            except queue.Empty:
                continue
            if frame is None:
                self._kill()
                raise WorkerFailure(StageStatus.ERROR, "WORKER_DIED")
            if frame.get("id") != rid:
                self._kill()  # out of step: never pair a reply with the wrong file
                raise WorkerFailure(StageStatus.ERROR, "WORKER_REPLY_MISMATCH")
            if not frame.get("ok"):
                code = str((frame.get("error") or {}).get("code", "WORKER_ERROR"))[:64]
                raise WorkerFailure(StageStatus.ERROR, code)
            result = frame.get("result")
            if not isinstance(result, dict):
                raise WorkerFailure(StageStatus.ERROR, "WORKER_BAD_REPLY")
            return result

    def _enter(self, deadline_ns: int, cancel: CancellationToken | None) -> None:
        # Calls are serialised, so one slow file must not hold up a caller past
        # its own deadline or cancellation.
        while True:
            if cancel is not None and cancel.cancelled():
                raise WorkerFailure(StageStatus.CANCELLED, "CANCELLED")
            remaining = (deadline_ns - time.monotonic_ns()) / 1e9
            if remaining <= 0:
                raise WorkerFailure(StageStatus.TIMEOUT, "WORKER_TIMEOUT")
            if self._lock.acquire(timeout=min(POLL_SECONDS, remaining)):
                return

    def call(self, op: str, args: dict[str, Any], *, deadline_ns: int,
             cancel: CancellationToken | None = None, handle_from: int | None = None) -> dict[str, Any]:
        self._enter(deadline_ns, cancel)
        try:
            # A worker that died between calls (crash, OOM kill, external
            # termination) is replaced before it can fail this request.
            if self._proc is not None and self._proc.wait(0) is not None:
                self._kill()
            if self._proc is None:
                try:
                    self._start(deadline_ns)
                except (OSError, WorkerFailure) as e:
                    self._kill()
                    raise WorkerFailure(StageStatus.UNAVAILABLE, "WORKER_UNAVAILABLE") from e
            if handle_from is not None:
                try:
                    args = {**args, "handle": self._duplicate(handle_from)}
                except WorkerFailure:
                    self._kill()  # a worker we cannot hand files to is not reused
                    raise
            return self._send(op, args, deadline_ns, cancel)
        finally:
            self._lock.release()

    def _duplicate(self, handle: int) -> int:
        assert self._proc is not None
        dst = wintypes.HANDLE()
        # Same (read-only, deny-write) access as the parent's handle; the
        # worker never gets the path, so it cannot open anything else by it.
        if not _k32.DuplicateHandle(_k32.GetCurrentProcess(), handle, self._proc._process,
                                    ctypes.byref(dst), 0, False, DUPLICATE_SAME_ACCESS):
            raise WorkerFailure(StageStatus.ERROR, "HANDLE_DUPLICATE_FAILED")
        return int(dst.value)


def _failed(engine_id: str, request: ScanRequest, identity: FileIdentity,
            status: StageStatus, code: str, start: int) -> EngineResult:
    return EngineResult(
        CONTRACT_VERSION, engine_id, request.file_id, identity, status, VerdictCode.UNKNOWN,
        Coverage(identity.size, (), "none", 0, 0, 0, 0, (), (), (), "unknown"), (), None, None, None,
        code, start, (time.monotonic_ns() - start) // 1_000_000,
        ScanError(code, "worker", code, True) if status is not StageStatus.CANCELLED else None)


class WorkerAdapter:
    """Gate v2 adapter whose parsing runs in the restricted worker."""

    reopens_path = False

    def __init__(self, session: WorkerSession, engine_id: str) -> None:
        self.session = session
        self.engine_id = engine_id

    def readiness(self) -> str:
        return "READY"

    def scan_bound(self, request: ScanRequest, identity: FileIdentity,
                   cancel: CancellationToken, reader: BoundReader) -> EngineResult:
        start = time.monotonic_ns()
        stream = getattr(reader, "_stream", None)  # the measured, deny-write handle
        # The worker gets the handle, never the location (R13b P5): the bare name
        # is all that deceptive-name checks need.
        unplaced = replace(identity, canonical_path=None)
        args: dict[str, Any] = {"engine": self.engine_id, "identity": unplaced.to_dict()}
        handle_from = None
        if stream is not None:
            import msvcrt

            handle_from = msvcrt.get_osfhandle(stream.fileno())
            named = replace(request, path=ntpath.basename(request.path)) if request.path else request
            args["request"] = named.to_dict()
        else:
            args["request"] = request.to_dict()
            if len(str(args["request"])) > MAX_FRAME - 64 * 1024:
                return _failed(self.engine_id, request, identity, StageStatus.ERROR, "TOO_LARGE_FOR_WORKER", start)
        try:
            reply = self.session.call("scan", args, deadline_ns=request.deadline_monotonic_ns,
                                      cancel=cancel, handle_from=handle_from)
            result = EngineResult.from_dict(reply.get("engine_result"))
        except WorkerFailure as e:
            return _failed(self.engine_id, request, identity, e.status, e.code, start)
        except (ContractError, TypeError, KeyError, ValueError):
            # Whatever the worker sent must pass the same contract checks as
            # an in-process adapter; malformed output is an error, not clean.
            return _failed(self.engine_id, request, identity, StageStatus.ERROR, "WORKER_BAD_RESULT", start)
        if result.engine_id != self.engine_id or result.file_id != request.file_id or result.identity != unplaced:
            return _failed(self.engine_id, request, identity, StageStatus.ERROR, "WORKER_RESULT_BINDING", start)
        return replace(result, identity=identity)
