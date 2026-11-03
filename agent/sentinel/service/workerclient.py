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
import logging
import ntpath
import os
import queue
import threading
import time
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import replace
from typing import Any

from ..gate_v2.content import BoundReader
from ..gate_v2.contract import (
    CONTRACT_VERSION, CancellationToken, ContractError, Coverage, EngineResult,
    FileIdentity, ScanError, ScanRequest, StageStatus, VerdictCode,
)
from . import worker as worker_mod
from .paths import active_version, installed_paths
from .protocol import MAX_FRAME, MAX_RULES_FRAME, ProtocolError, read_frame, write_frame

log = logging.getLogger(__name__)

POLL_SECONDS = 0.05
START_SECONDS = 30.0
EXIT_WAIT_SECONDS = 1.0

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
        # A Windows code, never file content, so `status` may show it. service.log is
        # for administrators, and a scan only sees a typed failure.
        self.last_failure = ""

    # -- lifecycle

    def _start(self, deadline_ns: int) -> None:
        version = active_version()
        if version is None:
            self._proc = worker_mod.launch(worker_mod.bootstrap("sentinel.service.workermain"),
                                           memory_limit=self._memory_limit)
        else:
            expected = installed_paths(version.name).version.resolve(strict=True)
            if version.resolve(strict=True) != expected:
                raise WorkerFailure(StageStatus.UNAVAILABLE, "INSTALL_INTEGRITY")
            from .installer import WindowsScm
            sid = WindowsScm().service_sid("SentinelGuard")
            self._proc = worker_mod.launch(["-m", "sentinel.service.workermain"],
                                           memory_limit=self._memory_limit, python=str(version / "python.exe"),
                                           cwd=str(version), service_sid=sid)
        self.starts += 1
        self._replies = queue.Queue()
        threading.Thread(target=self._pump, args=(self._proc, self._replies), daemon=True,
                         name="worker-reader").start()
        started_by = min(deadline_ns, time.monotonic_ns() + int(START_SECONDS * 1e9))
        reply = self._send("init", self._init_args, started_by, None, limit=MAX_RULES_FRAME)
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

    def _died(self) -> WorkerFailure:
        code = self._proc.wait(EXIT_WAIT_SECONDS) if self._proc is not None else None
        self.last_failure = "still running" if code is None else f"exit {code:#x}"
        self._kill()
        return WorkerFailure(StageStatus.ERROR, "WORKER_DIED")

    def close(self) -> None:
        with self._lock:
            self._kill()

    # -- calls

    def _send(self, op: str, args: dict[str, Any], deadline_ns: int,
              cancel: CancellationToken | None, *, limit: int = MAX_FRAME) -> dict[str, Any]:
        assert self._proc is not None
        self._next_id += 1
        rid = self._next_id
        try:
            write_frame(self._proc.stdin, {"id": rid, "op": op, "args": args}, limit=limit)
        except (OSError, ProtocolError) as e:
            raise self._died() from e
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
                raise self._died()
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
                    if isinstance(e, OSError):
                        self.last_failure = str(e)
                    log.warning("worker did not start: %s (%s)", self.last_failure, getattr(e, "code", ""))
                    raise WorkerFailure(StageStatus.UNAVAILABLE, "WORKER_UNAVAILABLE") from e
                self.last_failure = ""
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


class Isolation:
    """What the Scanner uses to run file parsing outside the privileged process."""

    def __init__(self) -> None:
        self.session: WorkerSession | None = None

    def load(self, json_packs: tuple[tuple[str, bytes, bool], ...],
             yara_sources: tuple[tuple[str, str, str], ...]) -> None:
        self.close()  # new rules: the running worker holds the old ones
        self.session = WorkerSession(json_packs=json_packs, yara_sources=yara_sources)

    def adapter(self, engine_id: str, known_bad: Callable[[str], str | None] | None = None) -> WorkerAdapter:
        assert self.session is not None
        return WorkerAdapter(self.session, engine_id, known_bad)

    def close(self) -> None:
        if self.session is not None:
            self.session.close()
            self.session = None

    def failure(self) -> str:
        return self.session.last_failure if self.session is not None else ""


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

    def __init__(self, session: WorkerSession, engine_id: str,
                 known_bad: Callable[[str], str | None] | None = None) -> None:
        self.session = session
        self.engine_id = engine_id
        self.known_bad = known_bad

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
        if self.known_bad is not None:
            args["known_bad"] = self.known_bad(identity.sha256)
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
