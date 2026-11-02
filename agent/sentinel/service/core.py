"""ServiceCore: the privileged side's request handling as a plain object.

The Windows service shell and the named-pipe server are thin wrappers around
this class; tests drive it in-process and over a same-user stream. Backends
(scanner, URL lookup, file-access check by impersonation, action execution)
are injected, so nothing here elevates or mutates the machine by itself.
"""

from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Protocol

from .authz import Caller, authorize
from .protocol import (
    PROTOCOL_VERSION, ProtocolError, error, ok, parse_request, read_frame, write_frame,
)

log = logging.getLogger(__name__)

PLAN_TTL_SECONDS = 120.0
MAX_PLANS_PER_CALLER = 8
MAX_JOBS_PER_CALLER = 64
MAX_JOBS = 4096
FINISHED_JOB_STATES = ("done", "cancelled", "failed")
MAX_SUMMARY = 500
NO_MATCH = "Tệp không khớp với nội dung được đề nghị tin cậy. Sẽ không có gì được tin cậy."
DRIVE_PATH = re.compile(r"[A-Za-z]:\\.+", re.DOTALL)
DEVICE_NAMES = frozenset(("CON", "PRN", "AUX", "NUL", *(f"{p}{n}" for p in ("COM", "LPT") for n in range(1, 10))))


def local_path(path: str) -> str | None:
    """The one spelling of a local file the service accepts, or None.

    Win32 treats "/" as "\\", so "\\/srv/share" is a UNC path a prefix test
    misses, and it reads every other form as well: a device name in any folder,
    a stream after a colon, names that silently lose trailing dots and spaces.
    A real path never needs any of those, and each one has been a way past a check.
    """
    text = path.replace("/", "\\")
    if not DRIVE_PATH.fullmatch(text):
        return None
    for part in text[3:].split("\\"):
        if (not part or part in (".", "..") or part != part.rstrip(". ") or ":" in part
                or any(ord(c) < 32 for c in part) or part.split(".")[0].upper() in DEVICE_NAMES):
            return None
    return text
RATE_CAPACITY = 60.0
RATE_PER_SECOND = 20.0


class Backend(Protocol):
    def status(self) -> dict[str, Any]: ...
    def check_url(self, url: str) -> dict[str, Any]: ...
    # Real service: impersonate the pipe client and open the path for reading,
    # so a user can never make the service scan (and later act on) a file that
    # user cannot read themselves (R13 §4).
    def can_read(self, caller: Caller, path: str) -> bool: ...
    def submit_scan(self, path: str, *, reason: str, url: str | None, caller: Caller) -> str: ...
    def job(self, job_id: str) -> dict[str, Any] | None: ...
    def cancel_job(self, job_id: str) -> bool: ...
    def enable_protection(self) -> dict[str, Any]: ...
    # Only what this caller may know about: another user's file paths stay theirs.
    def quarantine_items(self, caller: Caller) -> list[dict[str, Any]]: ...
    def allowed_hosts(self, offset: int, limit: int) -> dict[str, Any]: ...
    def events_for(self, caller: Caller, after: int, limit: int) -> dict[str, Any]: ...
    # Vietnamese summary built by the service from its own state, or None when
    # the target does not exist (unknown quarantine id, ...).
    def describe_plan(self, kind: str, params: dict[str, Any]) -> str | None: ...
    def execute_plan(self, kind: str, params: dict[str, Any]) -> dict[str, Any]: ...


@dataclass
class _Plan:
    plan_id: str
    version: int
    kind: str
    params: dict[str, Any]
    summary: str
    requester: tuple[str, int]
    expires: float
    claimed_by: tuple[tuple[str, int], str | None] | None = None


@dataclass
class _Bucket:
    tokens: float = RATE_CAPACITY
    stamp: float = field(default=0.0)


class ServiceCore:
    def __init__(self, backend: Backend, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.backend = backend
        self._clock = clock
        self._lock = threading.Lock()
        self._plans: dict[str, _Plan] = {}
        self._jobs: dict[str, tuple[str, int]] = {}  # job id -> owner
        self._buckets: dict[tuple[str, int], _Bucket] = {}
        self._stopping = False

    def stop(self) -> None:
        with self._lock:
            self._stopping = True

    # -- entry points

    def handle(self, caller: Caller, frame: dict[str, Any], *, connection_id: str | None = None) -> dict[str, Any]:
        """One request frame in, one response frame out; never raises."""
        rid = frame.get("id") if isinstance(frame.get("id"), int) and not isinstance(frame.get("id"), bool) else None
        try:
            req = parse_request(frame)
            denied = authorize(caller, req.op)
            if denied:
                return error(req.id, denied)
            if not self._take_token(caller):
                return error(req.id, "RATE_LIMITED")
            with self._lock:
                stopping = self._stopping
            if stopping and req.op.name not in ("hello", "status"):
                return error(req.id, "STOPPING")
            if req.op.name in ("get_plan", "approve_plan"):
                result = getattr(self, "_op_" + req.op.name)(caller, req.args, connection_id=connection_id)
            else:
                result = getattr(self, "_op_" + req.op.name)(caller, req.args)
            return ok(req.id, result)
        except ProtocolError as e:
            return error(rid, e.code, str(e))
        except Exception:
            # Backend errors can carry paths or raw engine output; the client
            # gets a code, the service log gets the details.
            log.exception("request failed")
            return error(rid, "INTERNAL")

    def serve(self, caller: Caller, inp: BinaryIO, out: BinaryIO) -> None:
        """One client connection: frames until end of stream or a framing error."""
        while True:
            try:
                frame = read_frame(inp)
            except ProtocolError as e:
                write_frame(out, error(None, e.code, str(e)))
                return
            if frame is None:
                return
            write_frame(out, self.handle(caller, frame))

    # -- helpers

    def _take_token(self, caller: Caller) -> bool:
        now = self._clock()
        with self._lock:
            b = self._buckets.get(caller.key)
            if b is None:
                if len(self._buckets) > 1024:
                    self._buckets.clear()  # bounded; a reset only refills buckets
                b = self._buckets[caller.key] = _Bucket(RATE_CAPACITY, now)
            b.tokens = min(RATE_CAPACITY, b.tokens + (now - b.stamp) * RATE_PER_SECOND)
            b.stamp = now
            if b.tokens < 1.0:
                return False
            b.tokens -= 1.0
            return True

    def _checked_path(self, caller: Caller, path: str) -> str:
        normal = local_path(path)
        if normal is None:
            raise ProtocolError("BAD_PATH", "only plain absolute local paths are accepted")
        if not self.backend.can_read(caller, normal):
            raise ProtocolError("ACCESS_DENIED", "the caller cannot read this file")
        return normal

    def _own_job(self, caller: Caller, job_id: str) -> None:
        with self._lock:
            owner = self._jobs.get(job_id)
        if owner != caller.key:
            # Same answer for "not yours" and "does not exist": job ids of
            # other users are not disclosed.
            raise ProtocolError("NOT_FOUND", "no such job")

    def _forget_finished(self, caller: Caller) -> None:
        # The limit is on work waiting, not on work ever done: without this a
        # caller would be refused for good after its 64th scan. Oldest first, so
        # a client still reading a recent result keeps it.
        with self._lock:
            mine = [job_id for job_id, owner in self._jobs.items()
                    if owner == caller.key and not job_id.startswith("pending-")]
        for job_id in mine[:max(0, len(mine) - MAX_JOBS_PER_CALLER // 2)]:
            info = self.backend.job(job_id)
            if info is None or info.get("state") in FINISHED_JOB_STATES:
                with self._lock:
                    self._jobs.pop(job_id, None)

    def _submit(self, caller: Caller, path: str, reason: str, url: str | None) -> dict[str, Any]:
        slot = "pending-" + secrets.token_hex(8)
        self._forget_finished(caller)
        with self._lock:
            mine = sum(1 for o in self._jobs.values() if o == caller.key)
            if mine >= MAX_JOBS_PER_CALLER or len(self._jobs) >= MAX_JOBS:
                raise ProtocolError("BUSY", "too many scans waiting")
            # Taken here, not after submitting: otherwise callers arriving
            # together all pass the check above.
            self._jobs[slot] = caller.key
        try:
            job_id = self.backend.submit_scan(path, reason=reason, url=url, caller=caller)
        except BaseException:
            with self._lock:
                del self._jobs[slot]
            raise
        with self._lock:
            del self._jobs[slot]
            self._jobs[job_id] = caller.key
        # Accepted for scanning, not scanned: the result comes from job_status.
        return {"job_id": job_id, "accepted": True}

    # -- user operations (never weaken protection)

    def _op_hello(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        return {"protocol": PROTOCOL_VERSION, "elevated_caller": caller.is_admin and caller.integrity in ("high", "system")}

    def _op_status(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        return self.backend.status()

    def _op_check_url(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        return self.backend.check_url(args["url"])

    def _op_download_hint(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        # The URL is provenance for the report, never authority to act (R13 §4).
        path = self._checked_path(caller, args["path"])
        return self._submit(caller, path, "download", args.get("url"))

    def _op_scan_request(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        path = self._checked_path(caller, args["path"])
        return self._submit(caller, path, "on_demand", None)

    def _op_job_status(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        self._own_job(caller, args["job_id"])
        info = self.backend.job(args["job_id"])
        if info is None:
            raise ProtocolError("NOT_FOUND", "no such job")
        return info

    def _op_cancel_job(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        self._own_job(caller, args["job_id"])
        return {"cancelled": self.backend.cancel_job(args["job_id"])}

    def _op_enable_protection(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        return self.backend.enable_protection()

    def _op_list_quarantine(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        return {"items": self.backend.quarantine_items(caller)}

    def _op_allowed_hosts(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        return self.backend.allowed_hosts(args["offset"], args["limit"])

    def _op_events(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        return self.backend.events_for(caller, args["after"], args["limit"])

    def _op_request_plan(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        params = dict(args["params"])
        if args["kind"] == "add_exclusion":
            # Whether a hash matches is an answer about the file: it has to be one
            # the caller may read, and the path must be as plain as any other.
            params["path"] = self._checked_path(caller, params["path"])
        summary = self.backend.describe_plan(args["kind"], params)
        if summary is None:
            if args["kind"] != "add_exclusion":
                raise ProtocolError("NOT_FOUND", "nothing to act on")
            # Whether a hash matches is an answer about a file, and the name can
            # be swapped after the access check. Only the elevated helper hears it.
            summary = NO_MATCH
        now = self._clock()
        with self._lock:
            self._expire(now)
            if sum(1 for p in self._plans.values() if p.requester == caller.key) >= MAX_PLANS_PER_CALLER:
                raise ProtocolError("BUSY", "too many pending confirmations")
            plan = _Plan(secrets.token_hex(16), 1, args["kind"], params, summary[:MAX_SUMMARY],
                         caller.key, now + PLAN_TTL_SECONDS)
            self._plans[plan.plan_id] = plan
        # The requester learns only the id; what gets approved is what the
        # service shows the elevated helper, not anything the requester said.
        return {"plan_id": plan.plan_id, "expires_in": int(PLAN_TTL_SECONDS)}

    # -- elevated operations (consent helper only)

    def _plan_for(self, caller: Caller, plan_id: str) -> _Plan:
        with self._lock:
            self._expire(self._clock())
            plan = self._plans.get(plan_id)
        # The helper runs in the requester's interactive session; an approval
        # from another session (or another machine user's desktop) is refused.
        if plan is None or plan.requester != caller.key:
            raise ProtocolError("NOT_FOUND", "no such confirmation (expired?)")
        return plan

    def _op_get_plan(self, caller: Caller, args: dict[str, Any], *, connection_id: str | None = None) -> dict[str, Any]:
        plan = self._plan_for(caller, args["plan_id"])
        with self._lock:
            if plan.claimed_by is not None:
                raise ProtocolError("PLAN_CLAIMED", "confirmation already displayed")
            plan.claimed_by = (caller.key, connection_id)
        return {"plan_id": plan.plan_id, "version": plan.version, "kind": plan.kind, "summary": plan.summary}

    def _op_approve_plan(self, caller: Caller, args: dict[str, Any], *, connection_id: str | None = None) -> dict[str, Any]:
        plan = self._plan_for(caller, args["plan_id"])
        if plan.claimed_by is not None and plan.claimed_by != (caller.key, connection_id):
            raise ProtocolError("PLAN_CLAIMED", "confirmation belongs to another helper")
        if args["version"] != plan.version:
            raise ProtocolError("STALE_PLAN", "the confirmation changed; show it again")
        current = self.backend.describe_plan(plan.kind, plan.params)
        if current is None or current[:MAX_SUMMARY] != plan.summary:
            raise ProtocolError("STALE_PLAN", "the target changed; show it again")
        with self._lock:
            # Single use: removed before acting, so a replayed approval finds nothing.
            if self._plans.pop(plan.plan_id, None) is None:
                raise ProtocolError("NOT_FOUND", "no such confirmation (expired?)")
        # The backend re-checks the target's current state (identity, hash)
        # before acting; the plan only says what the user agreed to.
        return self.backend.execute_plan(plan.kind, plan.params)

    def _expire(self, now: float) -> None:
        for pid in [pid for pid, p in self._plans.items() if p.expires <= now]:
            del self._plans[pid]
