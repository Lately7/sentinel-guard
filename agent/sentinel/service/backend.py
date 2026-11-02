"""What the service does to the machine: the real Backend of ServiceCore.

Scans run with parsing in the restricted worker and acting here, behind the
protection barrier. Nothing a client says decides anything: the client names a
file, the service scans it itself and acts on its own result.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import re
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import __version__, config, feeds, quarantine, urlintel, yarafeed
from ..db import Database
from ..engine import clamav
from ..engine.scanner import Scanner
from ..engine.signatures import SignatureEngine
from ..engine.verdict import Verdict
from ..gate_v2 import identity, scope
from ..gate_v2.actions import ProtectionBarrier, ProtectionStopped
from ..protection import act_on, escalate_origin, top_reason
from . import winpipe
from .authz import Caller
from .observers import DbCursorStore, Observers
from .procwatch import ProcessWatcher, windows_resolve, windows_snapshot
from .protocol import ProtocolError
from .rescan import DbDownloadStore, Download, RescanQueue
from .usn import WindowsVolume

log = logging.getLogger(__name__)

SCAN_THREADS = 2
MAX_KEPT_JOBS = 4096
# Work nobody asked for waits behind work somebody is waiting on, and it is bounded:
# past this a burst of changes is counted and left to the next reconciliation.
MAX_OBSERVED = 2048
# A stop or an approved "off" waits this long for an action already running.
OFF_BARRIER_SECONDS = 20.0
MAINTENANCE_SECONDS = 600.0
PAGE_BYTES = 600_000  # a frame holds 1 MiB, and a page of long names can exceed that
HOST = re.compile(r"(?=.{1,253}\Z)[a-z0-9-]+(\.[a-z0-9-]+)*\Z")
OFF_META = "protection_off"
SOURCES = {"download": "download", "on_demand": "scan", "journal": "realtime", "process": "realtime",
           "reconcile": "realtime", "rescan": "rescan"}


def shown(text: str) -> str:
    """Text from a file name or a page, safe to put in a confirmation.

    Direction overrides and control characters are how a name is made to read
    as something else in the one prompt the user trusts.
    """
    return "".join(c for c in text if c.isprintable())[:300]


class _Cancel:
    def __init__(self) -> None:
        self._set = threading.Event()

    def cancel(self) -> None:
        self._set.set()

    def cancelled(self) -> bool:
        return self._set.is_set()


@dataclass
class _Job:
    job_id: str
    path: str
    reason: str
    url: str | None
    owner: str
    token: int | None
    cancel: _Cancel = field(default_factory=_Cancel)
    state: str = "queued"
    result: dict[str, Any] = field(default_factory=dict)
    use_cache: bool = True


class ProductBackend:
    def __init__(self, db: Database, settings: config.Settings, scanner: Scanner, *,
                 barrier: ProtectionBarrier | None = None,
                 readable: Callable[[int | None, str], bool] = winpipe.client_can_read,
                 own_token: Callable[[int], int] = winpipe.duplicate_token,
                 drop_token: Callable[[int], None] = winpipe.close_token,
                 file_owner: Callable[[str], str | None] = winpipe.file_owner,
                 observers: Callable[[ProductBackend], Observers | None] = lambda backend: None) -> None:
        self.db = db
        self.settings = settings
        self.scanner = scanner
        self.barrier = barrier or ProtectionBarrier()
        self._readable = readable
        self._own_token = own_token
        self._drop_token = drop_token
        self._file_owner = file_owner
        self._jobs: OrderedDict[str, _Job] = OrderedDict()
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=SCAN_THREADS, thread_name_prefix="service-scan")
        self._observed_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="service-observed")
        self._observed = threading.BoundedSemaphore(MAX_OBSERVED)
        self._stop = threading.Event()
        self._maintenance: threading.Thread | None = None
        self.rescans = RescanQueue(DbDownloadStore(db))
        self._rule_generation: str | None = None
        self.observers = observers(self)

    # -- lifecycle

    def start(self) -> None:
        self.db.check_and_repair()
        self.db.prune_cache()
        quarantine.reconcile(self.db)
        if self.db.get_meta(OFF_META, ""):
            self.barrier.revoke(0)  # "off" was approved; a restart must not undo it
        self._maintenance = threading.Thread(target=self._maintain, name="service-maintenance", daemon=True)
        self._maintenance.start()
        if self.observers is not None:
            self.observers.start()

    def stop(self, timeout: float) -> bool:
        """True once no action can run. Safe to call again while it answers False."""
        self._stop.set()
        if self.observers is not None:
            self.observers.stop()
        closed = self.barrier.revoke(timeout)
        with self._lock:
            jobs = list(self._jobs.values())
        for job in jobs:
            job.cancel.cancel()
        if closed:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._observed_pool.shutdown(wait=False, cancel_futures=True)
            if self.scanner.isolation is not None:
                self.scanner.isolation.close()
        return closed

    def _maintain(self) -> None:
        while not self._stop.wait(MAINTENANCE_SECONDS):
            try:
                quarantine.reconcile(self.db)
                self.db.prune_cache()
                if feeds.is_due(self.db, self.settings.feed_interval_hours):
                    feeds.update_all(self.db)
                if feeds.engine_update_due(self.db, "yara", 24 * 3600):
                    res = yarafeed.update()
                    feeds.record_engine_update(self.db, "yara", res)
                    if res.startswith("ok"):
                        self.scanner.sigs = SignatureEngine(self.db)
                self.rescan_on_new_rules()
            except Exception:
                log.exception("maintenance failed")

    def rescan_on_new_rules(self) -> None:
        generation = self.scanner.gate_id()
        if self._rule_generation not in (None, generation):
            self.rescans.signatures_changed(generation)
            while (item := self.rescans.pop()) is not None:
                self.observe(item.path, "rescan", True)
        self._rule_generation = generation

    # -- reads

    def status(self) -> dict[str, Any]:
        return {"version": __version__, "realtime": self.barrier.current() is not None,
                "quarantined": len(self.db.quarantine_items()), "blocklist_version": self.db.get_meta("blocklist_version", "0"),
                "allow_version": self.db.allow_version(),
                # Said out loud: seeing a file after it appeared is not stopping it.
                "observation": self.observers.report() if self.observers is not None else {"prevention": "none"}}

    def check_url(self, url: str) -> dict[str, Any]:
        return urlintel.check(self.db, url)

    def can_read(self, caller: Caller, path: str) -> bool:
        return self._readable(caller.token, path)

    def allowed_hosts(self, offset: int, limit: int) -> dict[str, Any]:
        everything = self.db.allowed_hosts()
        page: list[str] = []
        size = 0
        for host in everything[offset:offset + limit]:
            size += len(host) + 4
            if size > PAGE_BYTES and page:
                break
            page.append(host)
        return {"allow_version": self.db.allow_version(), "total": len(everything), "offset": offset, "hosts": page}

    def quarantine_items(self, caller: Caller) -> list[dict[str, Any]]:
        items = []
        for item in self.db.quarantine_items():
            if caller.is_admin or _owner(item) == caller.sid:
                items.append({"id": item["id"], "original_path": item["original_path"], "sha256": item["sha256"],
                              "size": item["size"], "ts": item["ts"]})
        return items

    # -- scans

    def submit_scan(self, path: str, *, reason: str, url: str | None, caller: Caller) -> str:
        if self._stop.is_set():
            raise ProtocolError("STOPPING", "the service is stopping")
        token = self._own_token(caller.token) if caller.token is not None else None
        job = _Job(uuid.uuid4().hex, path, reason, url, caller.sid, token)
        with self._lock:
            self._jobs[job.job_id] = job
            self._trim()
        self._pool.submit(self._run, job)
        return job.job_id

    def observe(self, path: str, reason: str, fresh: bool = False) -> bool:
        """Work the service gave itself; False when the queue is full."""
        if self._stop.is_set() or not self._observed.acquire(blocking=False):
            return False
        job = _Job(uuid.uuid4().hex, path, reason, None, self._file_owner(path) or "", None, use_cache=not fresh)
        try:
            self._observed_pool.submit(self._run_observed, job)
        except RuntimeError:  # the pool is shutting down
            self._observed.release()
            return False
        return True

    def _run_observed(self, job: _Job) -> None:
        try:
            self._run(job)
        finally:
            self._observed.release()

    def _trim(self) -> None:
        for job_id in list(self._jobs):
            if len(self._jobs) <= MAX_KEPT_JOBS:
                return
            if self._jobs[job_id].state in ("done", "cancelled", "failed"):
                del self._jobs[job_id]

    def job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return {"job_id": job_id, "state": job.state, **job.result} if job is not None else None

    def cancel_job(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None or job.state in ("done", "cancelled", "failed"):
            return False
        job.cancel.cancel()
        return True

    def _run(self, job: _Job) -> None:
        try:
            if job.cancel.cancelled():
                job.state = "cancelled"
                return
            job.state = "running"
            verdict = self.scanner.scan_file(job.path, barrier=self.barrier, cancel=job.cancel, use_cache=job.use_cache)
            reputation = urlintel.check(self.db, job.url) if job.url else None
            escalate_origin(verdict, reputation)
            if job.cancel.cancelled() and verdict.label != "malicious":
                job.state = "cancelled"
                return
            job.result = self._finish(job, verdict, reputation)
            job.state = "done"
        except Exception:
            log.exception("scan job failed")
            job.result = {"code": "SCAN_FAILED"}
            job.state = "failed"
        finally:
            if job.token is not None:
                self._drop_token(job.token)
                job.token = None

    def _finish(self, job: _Job, verdict: Verdict, reputation: dict[str, Any] | None) -> dict[str, Any]:
        # The name may have been re-pointed since the client's access was checked:
        # what was really measured is what the client must be allowed to read,
        # or it learns about (and acts on) a file that is none of its business.
        measured = verdict.decision.identity.canonical_path if getattr(verdict, "decision", None) else None
        if job.token is not None and measured and not self._readable(job.token, measured):
            return {"code": "ACCESS_DENIED"}
        source = SOURCES.get(job.reason, "scan")
        owner = {"owner_sid": job.owner}
        try:
            with self.barrier.action():
                outcome = act_on(self.db, verdict, self.settings, source, extra=owner, authority=True)
        except ProtectionStopped:
            outcome = act_on(self.db, verdict, dataclasses.replace(self.settings, auto_quarantine=False), source,
                             extra=owner, authority=True)
        decision = getattr(verdict, "decision", None)
        result = {**outcome, "verdict": verdict.to_dict(max_findings=30), "reason": top_reason(verdict),
                  "url_reputation": reputation,
                  "engines": sorted(r.engine_id for r in decision.engine_results) if decision else [],
                  "trusted": bool(decision) and "USER_TRUST" in decision.reason_codes}
        if outcome.get("error"):
            result["code"] = "NOT_QUARANTINED"
        if job.reason == "download" and decision is not None and not outcome["quarantined"]:
            self._remember_download(job, decision)
        return result

    def _remember_download(self, job: _Job, decision: Any) -> None:
        seen = decision.identity
        if seen.volume_serial is not None and seen.file_id_hex is not None:
            self.rescans.remember(Download(seen.volume_serial, int(seen.file_id_hex, 16), job.path, seen.sha256,
                                           self.scanner.gate_id(), time.time()))

    # -- plans

    def enable_protection(self) -> dict[str, Any]:
        self.db.set_meta(OFF_META, "")
        self.barrier.resume()
        self.db.add_event("system", "info", "Bảo vệ đã bật lại", "")
        return {"realtime": True}

    def describe_plan(self, kind: str, params: dict[str, Any]) -> str | None:
        if kind == "disable_protection":
            return "Tắt bảo vệ của Sentinel Guard trên máy này cho tới khi bật lại."
        if kind == "trust_host":
            host = _host(params["host"])
            return None if host is None else f"Luôn tin cậy trang web {host}: trang này sẽ không còn bị chặn hay cảnh báo."
        if kind in ("restore_quarantine", "delete_quarantine"):
            item = self.db.quarantine_item(params["quarantine_id"])
            if item is None:
                return None
            where = shown(item["original_path"])
            if kind == "delete_quarantine":
                return f"Xóa vĩnh viễn bản cách ly của {where}. Không khôi phục lại được."
            return (f"Khôi phục {where}, SHA-256 {item['sha256'][:16]}. Chỉ tệp này ở đúng vị trí này được bỏ qua "
                    "khi quét; bản sao ở nơi khác vẫn bị chặn.")
        if kind == "add_exclusion":
            found = identity.measure(params["path"], max_bytes=config.MAX_SCAN_BYTES)
            if not found.ok or found.identity is None or found.identity.sha256 != params["sha256"].lower():
                return None
            return (f"Luôn tin cậy nội dung của {shown(params['path'])}, SHA-256 {found.identity.sha256[:16]}: "
                    "mọi bản sao của nội dung này trên máy sẽ được bỏ qua khi quét.")
        return None

    def execute_plan(self, kind: str, params: dict[str, Any]) -> dict[str, Any]:
        if kind == "disable_protection":
            # Off is written down only once the action boundary is closed (invariant 11).
            closed = self.barrier.revoke(OFF_BARRIER_SECONDS)
            self.db.set_meta(OFF_META, "1")
            self.db.add_event("system", "warning", "Bảo vệ đã TẮT", "Tắt sau khi người quản trị xác nhận.")
            return {"realtime": False, "barrier_closed": closed}
        if kind == "trust_host":
            host = _host(params["host"])
            if host is None:
                raise ProtocolError("BAD_REQUEST", "invalid host")
            self.db.allow_host(host)
            self.db.add_event("web", "warning", "Đã tin cậy trang web", host, {"host": host})
            return {"host": host}
        if kind == "restore_quarantine":
            try:
                target = quarantine.restore(self.db, params["quarantine_id"])
            except quarantine.QuarantineError as e:
                raise ProtocolError("ACTION_FAILED", e.code) from e
            self.db.add_event("system", "warning", "Đã khôi phục tệp", shown(str(target)))
            return {"restored": str(target)}
        if kind == "delete_quarantine":
            quarantine.delete(self.db, params["quarantine_id"])
            return {"deleted": True}
        if kind == "add_exclusion":
            self.db.allow_hash(params["sha256"])
            self.db.bump_generation()
            self.db.add_event("system", "warning", "Đã tin cậy nội dung tệp", shown(params["path"]),
                              {"sha256": params["sha256"]})
            return {"trusted": True}
        raise ProtocolError("NOT_FOUND", "nothing to act on")


def _owner(item: dict[str, Any]) -> str | None:
    try:
        return json.loads(item["verdict"]).get("owner_sid")
    except (ValueError, AttributeError):
        return None


def _host(host: str) -> str | None:
    host = host.lower().strip(".")
    try:
        # Shown as it resolves: a look-alike Unicode name must not pass for the real one.
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return ascii_host if HOST.fullmatch(ascii_host) else None


def _machine_observers(backend: ProductBackend) -> Observers:
    volumes = []
    for root in scope.fixed_drives():
        try:
            volumes.append(WindowsVolume(root))
        except OSError:
            log.warning("no journal for %s", root)

    def reconcile() -> None:
        # Autostart and what is running now; the folders of each user are the tray's.
        for target in scope.discover("smart", scope.windows_sources("smart", []), data_root=str(config.data_dir())):
            if not backend.observe(target.path, "reconcile"):
                return

    return Observers(backend.observe, volumes, DbCursorStore(backend.db),
                     processes=ProcessWatcher(windows_snapshot, windows_resolve), rescans=backend.rescans,
                     reconcile=reconcile, data_root=str(config.data_dir()))


def build(state_db: Path | None = None) -> ProductBackend:
    from .workerclient import Isolation

    clamav.machine_only = True
    db = Database(state_db)
    settings = config.Settings.load()
    # No clamd here yet: it parses hostile files and must not do that as LocalSystem.
    # Until it can run restricted, a ClamAV hit stays with the user's own process
    # (bridge.ServiceLease.confirm) instead of a parser running with full rights.
    scanner = Scanner(db, use_defender=settings.use_defender, use_clamav=False, isolation=Isolation())
    return ProductBackend(db, settings, scanner, observers=_machine_observers)
