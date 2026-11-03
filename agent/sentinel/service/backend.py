"""What the service does to the machine: the real Backend of ServiceCore.

Scans run with parsing in the restricted worker and acting here, behind the
protection barrier. Nothing a client says decides anything: the client names a
file, the service scans it itself and acts on its own result.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import queue
import re
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
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
from ..protection import act_on, top_reason
from . import repair, winpipe
from .authz import Caller
from .observers import DbCursorStore, Observers
from .procwatch import ProcessWatcher, windows_resolve, windows_snapshot
from .protocol import ProtocolError
from .repair import shown, shown_path
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
FIRST_MAINTENANCE_SECONDS = 30.0  # a fresh install has no threat data at all until this runs
MAX_REPAIRS = 64
WATCH_SECONDS = 5.0
# A job past this is written off: opening a file can wait on a hostile oplock for
# ever and nothing can interrupt it. Past MAX_STUCK at once, no more threads.
STALL_SECONDS = config.SCAN_DEADLINE_SECONDS + 30.0
MAX_STUCK = 16
OBSERVED_STALL_SECONDS = 60.0  # one must not hold up the next, and a slow scan just carries on
USER_SIDS = ("S-1-5-21-", "S-1-12-1-")  # local or domain, and Entra ID
# A file that would not hold still is looked at again, a few times, then reported.
RETRY_SECONDS = (5.0, 30.0, 120.0, 600.0)
MAX_RETRIES = 1024
PAGE_BYTES = 600_000  # a frame holds 1 MiB, and a page of long names can exceed that
MAX_EVENT_TEXT = 1000
HOST = re.compile(r"(?=.{1,253}\Z)[a-z0-9-]+(\.[a-z0-9-]+)*\Z")
OFF_META = "protection_off"
SOURCES = {"download": "download", "on_demand": "scan", "journal": "realtime", "process": "realtime",
           "reconcile": "realtime", "rescan": "rescan"}


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
    attempts: int = 0


class _Lane:
    """Worker threads a stuck file cannot use up.

    A job past `limit` gets its place taken by a new thread, and goes on: it may
    only be slow. Past `give_up` it is reported and cancelled. A stuck thread
    gives its place back when its open finally returns.
    """

    def __init__(self, name: str, workers: int, run: Callable[[_Job], None], *, limit: float = STALL_SECONDS,
                 give_up: float | None = None, clock: Callable[[], float] = time.monotonic,
                 on_stall: Callable[[_Job], None] = lambda job: None) -> None:
        self.name, self.run, self.limit, self.clock, self.on_stall = name, run, limit, clock, on_stall
        self.give_up = limit if give_up is None else give_up
        self.jobs: queue.SimpleQueue[_Job] = queue.SimpleQueue()
        self.running: dict[threading.Thread, list[Any]] = {}  # job, started, given up on
        self.replaced: set[threading.Thread] = set()
        self.stalled = 0  # ever
        self.stuck = 0  # right now
        self.missing = 0  # replacements not started because too many are stuck
        self._lock = threading.Lock()
        self._stop = threading.Event()
        for _ in range(workers):
            self._add()

    def _add(self) -> None:
        threading.Thread(target=self._work, name=f"service-{self.name}", daemon=True).start()

    def submit(self, job: _Job) -> None:
        self.jobs.put(job)

    def stop(self) -> None:
        self._stop.set()

    def _work(self) -> None:
        me = threading.current_thread()
        while not self._stop.is_set():
            try:
                job = self.jobs.get(timeout=0.2)
            except queue.Empty:
                continue
            with self._lock:
                self.running[me] = [job, self.clock(), False]
            done = False
            try:
                self.run(job)
            finally:
                with self._lock:
                    del self.running[me]
                    if me in self.replaced:
                        self.replaced.discard(me)
                        self.stuck -= 1
                        if self.missing:
                            self.missing -= 1  # stays on, in the place nobody could fill
                        else:
                            done = True
            if done:
                return

    def sweep(self) -> None:
        now = self.clock()
        spare = 0
        abandoned: list[_Job] = []
        with self._lock:
            for thread, entry in self.running.items():
                age = now - entry[1]
                if age > self.limit and thread not in self.replaced:
                    self.replaced.add(thread)
                    self.stalled += 1
                    self.stuck += 1
                    if self.stuck <= MAX_STUCK:
                        spare += 1
                    else:
                        self.missing += 1
                if age > self.give_up and not entry[2]:
                    entry[2] = True
                    abandoned.append(entry[0])
        for _ in range(spare):
            self._add()
        for job in abandoned:
            job.cancel.cancel()
            job.result, job.state = {"code": "STALLED"}, "failed"
            self.on_stall(job)


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
        self._asked_lane = _Lane("scan", SCAN_THREADS, self._run)
        self._observed_lane = _Lane("observed", 1, self._run_observed, limit=OBSERVED_STALL_SECONDS,
                                    give_up=STALL_SECONDS, on_stall=self._gave_up)
        self._observed = threading.BoundedSemaphore(MAX_OBSERVED)
        self._later: list[tuple[float, str, str, int]] = []
        self._stop = threading.Event()
        self._maintenance: threading.Thread | None = None
        self.rescans = RescanQueue(DbDownloadStore(db))
        self._repairs: OrderedDict[str, repair.Repair] = OrderedDict()
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
        threading.Thread(target=self._watch, name="service-watch", daemon=True).start()
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
            self._asked_lane.stop()
            self._observed_lane.stop()
            if self.scanner.isolation is not None:
                self.scanner.isolation.close()
        return closed

    def _maintain(self) -> None:
        wait = FIRST_MAINTENANCE_SECONDS
        while not self._stop.wait(wait):
            wait = MAINTENANCE_SECONDS
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

    def _watch(self) -> None:
        while not self._stop.wait(WATCH_SECONDS):
            try:
                self._asked_lane.sweep()
                self._observed_lane.sweep()
                self._retry_due()
            except Exception:
                log.exception("watch failed")

    def _retry_due(self) -> None:
        now = time.monotonic()
        with self._lock:
            due = [item for item in self._later if item[0] <= now]
            self._later = [item for item in self._later if item[0] > now]
        for _, path, reason, attempts in due:
            if not self.observe(path, reason, attempts=attempts):
                with self._lock:
                    self._later.append((now + WATCH_SECONDS, path, reason, attempts))

    def rescan_on_new_rules(self) -> None:
        generation = self.scanner.gate_id()
        if self._rule_generation not in (None, generation):
            self.rescans.signatures_changed(generation)
            while (item := self.rescans.pop()) is not None:
                if not self.observe(item.path, "rescan", True):
                    return  # the generation stays old, so the next round asks again
        self._rule_generation = generation

    # -- reads

    def status(self) -> dict[str, Any]:
        return {"version": __version__, "realtime": self.barrier.current() is not None,
                "quarantined": len(self.db.quarantine_items()), "blocklist_version": self.db.get_meta("blocklist_version", "0"),
                "allow_version": self.db.allow_version(),
                # Said out loud: seeing a file after it appeared is not stopping it.
                "observation": self.observers.report() if self.observers is not None else {"prevention": "none"},
                "stalled": self._asked_lane.stalled + self._observed_lane.stalled,
                "worker_failure": self.scanner.isolation.failure() if self.scanner.isolation is not None else ""}

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
            if _visible(caller, _owner(item)):
                items.append({"id": item["id"], "original_path": quarantine.real_path(item["original_path"]),
                              "sha256": item["sha256"], "size": item["size"], "ts": item["ts"]})
        return items

    def events_for(self, caller: Caller, after: int, limit: int) -> dict[str, Any]:
        """What happened since `after`: what the service does alone reaches its owner this way."""
        shown_rows: list[dict[str, Any]] = []
        last, size = after, 0
        for row in self.db.events_after(after, limit):
            try:
                data = json.loads(row["data"]) if row["data"] else {}
            except ValueError:
                data = {}
            if _visible(caller, data.get("owner_sid")) and (caller.is_admin or not data.get("admin_only")):
                entry = {"id": row["id"], "ts": row["ts"], "level": row["level"], "title": row["title"],
                         "detail": row["detail"][:MAX_EVENT_TEXT], "repair_id": data.get("repair_id")}
                # Bounded by what it encodes to: a page over the frame limit would
                # fail, `after` could not move, and nothing later would ever arrive.
                size += len(json.dumps(entry))
                if size > PAGE_BYTES:
                    break
                shown_rows.append(entry)
            last = row["id"]
        return {"events": shown_rows, "last": last}

    # -- scans

    def submit_scan(self, path: str, *, reason: str, url: str | None, caller: Caller) -> str:
        if self._stop.is_set():
            raise ProtocolError("STOPPING", "the service is stopping")
        token = self._own_token(caller.token) if caller.token is not None else None
        job = _Job(uuid.uuid4().hex, path, reason, url, caller.sid, token)
        with self._lock:
            self._jobs[job.job_id] = job
            self._trim()
        self._asked_lane.submit(job)
        return job.job_id

    def observe(self, path: str, reason: str, fresh: bool = False, *, attempts: int = 0) -> bool:
        """Work the service gave itself; False when the queue is full."""
        if self._stop.is_set() or not self._observed.acquire(blocking=False):
            return False
        self._observed_lane.submit(_Job(uuid.uuid4().hex, path, reason, None, "", None, use_cache=not fresh,
                                        attempts=attempts))
        return True

    def _run_observed(self, job: _Job) -> None:
        try:
            # In the lane, never in the caller: looking up an owner opens the file,
            # and the journal thread must not wait on anybody's oplock.
            job.owner = self._file_owner(job.path) or ""
            self._run(job)
            self._after_observed(job)
        except Exception:
            log.exception("observed job failed")
        finally:
            self._observed.release()

    def _after_observed(self, job: _Job) -> None:
        verdict = job.result.get("verdict") or {}
        unfinished = (job.state == "failed" or job.result.get("code") == "CHANGED"
                      or verdict.get("label") == "unknown")
        if not unfinished or not os.path.lexists(job.path):
            return
        if job.attempts < len(RETRY_SECONDS):
            with self._lock:
                if len(self._later) < MAX_RETRIES:
                    self._later.append((time.monotonic() + RETRY_SECONDS[job.attempts], job.path, job.reason,
                                        job.attempts + 1))
                    return
        self._gave_up(job)

    def _gave_up(self, job: _Job) -> None:
        self.db.add_event("realtime", "warning", "Chưa kiểm tra xong tệp",
                          f"{shown_path(job.path)}: tệp liên tục bị giữ hoặc thay đổi. Hãy chạy Quét ngay để thử lại.",
                          {"owner_sid": job.owner, "path": job.path})

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
            # The client names the URL, so it can name any listed address: reported
            # to the browser, and never a reason to touch a file (R13 §4).
            reputation = urlintel.check(self.db, job.url) if job.url else None
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
        decision = getattr(verdict, "decision", None)
        seen = decision.identity if decision is not None else None  # none: the file could not be opened
        measured = seen.canonical_path if seen is not None else None
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
        result = {**outcome, "verdict": verdict.to_dict(max_findings=30), "reason": top_reason(verdict),
                  "url_reputation": reputation,
                  # Only what really looked: "found nothing" means nothing from the others.
                  "engines": sorted(r.engine_id for r in decision.engine_results
                                    if r.status.value in ("completed", "partial")) if decision else [],
                  "trusted": bool(decision) and "USER_TRUST" in decision.reason_codes}
        if reputation and reputation.get("verdict") == "malicious" and not outcome["quarantined"]:
            self.db.add_event("download", "warning", "Tải về từ nguồn bị chặn", shown_path(job.path),
                              {**owner, "source": reputation.get("matched")})
        if outcome.get("code") == "IN_USE" and seen is not None:
            result["repair_id"] = self._offer_repair(verdict, seen.sha256, job.owner)
        if job.reason == "download" and seen is not None and not outcome["quarantined"]:
            self._remember_download(job, seen)
        return result

    def _offer_repair(self, verdict: Verdict, sha256: str, owner: str) -> str | None:
        with self._lock:
            for known in self._repairs.values():
                if known.path == str(verdict.path) and known.sha256 == sha256:
                    return known.repair_id
        try:
            proposal = repair.plan(str(verdict.path), sha256)
        except (repair.RepairError, OSError):
            return None
        with self._lock:
            self._repairs[proposal.repair_id] = proposal
            while len(self._repairs) > MAX_REPAIRS:
                self._repairs.popitem(last=False)
        # Found with nobody watching, it still has to reach somebody.
        self.db.add_event("realtime", "threat", "Chương trình độc hại đang chạy", shown_path(proposal.path),
                          {"owner_sid": owner, "repair_id": proposal.repair_id})
        return proposal.repair_id

    def _remember_download(self, job: _Job, seen: Any) -> None:
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
            where = shown_path(quarantine.real_path(item["original_path"]))
            if kind == "delete_quarantine":
                return f"Xóa vĩnh viễn bản cách ly của {where}. Không khôi phục lại được."
            return (f"Khôi phục {where}, SHA-256 {item['sha256'][:16]}. Chỉ tệp này ở đúng vị trí này được bỏ qua "
                    "khi quét; bản sao ở nơi khác vẫn bị chặn.")
        if kind == "approve_repair":
            with self._lock:
                proposal = self._repairs.get(params["repair_id"])
            return None if proposal is None else repair.describe(proposal)
        if kind == "add_exclusion":
            found = identity.measure(params["path"], max_bytes=config.MAX_SCAN_BYTES)
            if not found.ok or found.identity is None or found.identity.sha256 != params["sha256"].lower():
                return None
            # What was measured, not what the caller typed: the two can differ.
            where = shown_path(found.identity.canonical_path or params["path"])
            return (f"Luôn tin cậy nội dung của {where}, SHA-256 {found.identity.sha256[:16]}: "
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
            back = repair.undo(self.db, params["quarantine_id"])
            self.db.add_event("system", "warning", "Đã khôi phục tệp", shown_path(str(target)), {"admin_only": True})
            return {"restored": str(target), "autostart_restored": back}
        if kind == "delete_quarantine":
            quarantine.delete(self.db, params["quarantine_id"])
            return {"deleted": True}
        if kind == "approve_repair":
            with self._lock:
                proposal = self._repairs.pop(params["repair_id"], None)
            if proposal is None:
                raise ProtocolError("NOT_FOUND", "nothing to act on")
            owner = self._file_owner(proposal.path) or ""  # asked first: the file is gone afterwards
            try:
                done = repair.execute(self.db, proposal, {"owner_sid": owner})
            except repair.RepairError as e:
                raise ProtocolError("ACTION_FAILED", e.code) from e
            self.db.add_event("system", "threat", "Đã xử lý chương trình đang chạy", shown_path(proposal.path),
                              {**done, "owner_sid": owner})
            return done
        if kind == "add_exclusion":
            self.db.allow_hash(params["sha256"])
            self.db.bump_generation()
            self.db.add_event("system", "warning", "Đã tin cậy nội dung tệp", shown_path(params["path"]),
                              {"sha256": params["sha256"], "admin_only": True})
            return {"trusted": True}
        raise ProtocolError("NOT_FOUND", "nothing to act on")


def _visible(caller: Caller, owner: str | None) -> bool:
    # A user's own file is private to them. One owned by Administrators or SYSTEM,
    # as anything an elevated process wrote is, must not reach nobody at all.
    return caller.is_admin or owner == caller.sid or not (owner or "").startswith(USER_SIDS)


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

    def reconcile() -> bool:
        # Autostart and what is running now; the folders of each user are the tray's.
        for target in scope.discover("smart", scope.windows_sources("smart", []), data_root=str(config.data_dir())):
            if not backend.observe(target.path, "reconcile"):
                return False  # still owed
        return True

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
