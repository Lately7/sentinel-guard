"""The user-level side of the action lease (R13b P9).

The tray, CLI and native host keep working on their own while no service is
installed. As soon as one answers, what they find is only a hint: the service
scans the file itself and is the only one that acts. A same-user process cannot
fake that answer, because ServiceClient checks who owns the pipe first.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from .. import protection
from ..engine.verdict import Verdict
from .client import ServiceClient, ServiceError, ServiceUnavailable, WrongServer
from .protocol import ProtocolError

log = logging.getLogger(__name__)

CHECK_SECONDS = 5.0
POLL_SECONDS = 0.2
JOB_SECONDS = 150.0
FINISHED = ("done", "cancelled", "failed")


class ServiceLease:
    def __init__(self, make_client: Any = ServiceClient) -> None:
        self.make_client = make_client
        self._lock = threading.Lock()
        self._checked = float("-inf")
        self._up = False

    def available(self) -> bool:
        now = time.monotonic()
        with self._lock:
            if now - self._checked < CHECK_SECONDS:
                return self._up
        up = self._hello()
        with self._lock:
            self._checked, self._up = now, up
        return up

    def _hello(self) -> bool:
        try:
            with self.make_client() as client:
                client.request("hello")
            return True
        except WrongServer:
            # Someone else holds the name: worth a line in the log, and not a service.
            log.warning("the service pipe is answered by something else")
            return False
        except (ServiceError, OSError, ProtocolError):
            return False

    def _gone(self) -> None:
        with self._lock:
            self._checked, self._up = float("-inf"), False

    def _call(self, op: str, **args: Any) -> dict[str, Any] | None:
        """None when no service answers; a refusal is raised for the caller to read."""
        if not self.available():
            return None
        try:
            with self.make_client() as client:
                return client.request(op, **args)
        except ServiceUnavailable:
            self._gone()
            return None

    def _query(self, op: str, **args: Any) -> dict[str, Any] | None:
        # For lookups with a local answer to fall back on: a refusal is just no answer.
        try:
            return self._call(op, **args)
        except ServiceError:
            return None

    def _scan(self, op: str, **args: Any) -> dict[str, Any] | None:
        try:
            with self.make_client() as client:
                job = client.request(op, **args)["job_id"]
                deadline = time.monotonic() + JOB_SECONDS
                while time.monotonic() < deadline:
                    info = client.request("job_status", job_id=job)
                    if info.get("state") in FINISHED:
                        return info
                    time.sleep(POLL_SECONDS)
                client.request("cancel_job", job_id=job)
                return {"code": "SERVICE_TIMEOUT", "state": "failed"}
        except ServiceUnavailable:
            self._gone()
            return None
        except ServiceError:
            # Refused or unable: this process still has its own rights, and using
            # them gains nothing a same-user process does not already have.
            return None
        except OSError:
            self._gone()
            return None

    def confirm(self, v: Verdict) -> dict[str, Any] | None:
        """protection.delegate: asks the service to scan and act on this file."""
        if not v.path or not self.available():
            return None
        done = self._scan("scan_request", path=str(v.path))
        return None if done is None or _left_to_us(v, done) else done

    def scan_download(self, path: str, url: str | None) -> dict[str, Any] | None:
        if not self.available():
            return None
        return self._scan("download_hint", path=path, **({"url": url} if url else {}))

    def quarantine_items(self) -> list[dict[str, Any]] | None:
        found = self._query("list_quarantine")
        return None if found is None else list(found.get("items", []))

    def allowed_hosts(self, offset: int, limit: int) -> dict[str, Any] | None:
        return self._query("allowed_hosts", offset=offset, limit=limit)

    def check_url(self, url: str) -> dict[str, Any] | None:
        return self._query("check_url", url=url)

    def status(self) -> dict[str, Any] | None:
        return self._query("status")

    def events(self, after: int) -> dict[str, Any] | None:
        return self._query("events", after=after)

    def enable_protection(self) -> bool:
        return self._query("enable_protection") is not None

    def approve(self, kind: str, params: dict[str, Any]) -> bool:
        """Asks for a plan and shows the elevated confirmation; True when it went through."""
        from .consent import ConsentError, launch_consent

        try:
            plan = self._call("request_plan", kind=kind, params=params)
            return plan is not None and launch_consent(str(plan["plan_id"]))
        except (ServiceError, ConsentError, OSError) as e:
            log.warning("confirmation of %s did not complete: %s", kind, e)
            return False


def _left_to_us(v: Verdict, done: dict[str, Any]) -> bool:
    """The service gave no answer about the bytes this process found something in.

    It failed, was refused the file, or found nothing without having run the
    engine that did. This process may act on a file it can reach anyway, so the
    detection stands. A service that looked with the same engines, or a trust an
    administrator approved, is an answer and overrides what was found here.
    """
    if done.get("state") != "done" or done.get("code") == "ACCESS_DENIED":
        return True
    if done.get("quarantined") or done.get("error") or done.get("trusted"):
        return False
    decision = getattr(v, "decision", None)
    accepted = set(decision.accepted_evidence_ids) if decision else set()
    hash_rules: set[str] = set()
    if decision:
        for result in decision.engine_results:
            for evidence in result.evidence:
                if evidence.evidence_id not in accepted or result.engine_id != "core":
                    continue
                if (evidence.signature_id or evidence.detail_code).upper() == "KNOWN_BAD_HASH":
                    source = "known_bad" if evidence.source_id == "sentinel-core" else evidence.source_id
                    hash_rules.add(f"hash.{source}")
    service_verdict = done.get("verdict") or {}
    # The file may have changed between the two scans: an answer about other
    # bytes says nothing about the ones this process found something in.
    if accepted and service_verdict.get("sha256") != getattr(v, "sha256", None):
        return True
    service_rules = {item.get("rule") for item in service_verdict.get("findings", ())
                     if isinstance(item, dict)}
    if hash_rules - service_rules:
        return True
    finders = {r.engine_id for r in decision.engine_results if any(e.evidence_id in accepted for e in r.evidence)} if decision else set()
    return bool(finders - set(done.get("engines", ())))


lease = ServiceLease()


def install() -> ServiceLease:
    """Called once by each process that must yield to a running service."""
    protection.delegate = lease.confirm
    return lease
