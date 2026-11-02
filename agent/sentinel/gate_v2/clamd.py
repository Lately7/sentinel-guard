"""Strict, identity-bound ClamAV INSTREAM adapter."""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from .content import BoundReader, ContentError
from .contract import (CONTRACT_VERSION, ByteRange, CancellationToken, Category,
                       EngineResult, Evidence, FileIdentity, ScanError,
                       ScanRequest, StageStatus, Strength, VerdictCode)
from .coverage import CoverageLedger
from .policy import classify_clamav_name
from .winnet import ExpectedDaemon, verify_connected_daemon

_REPLY_CAP = 4096
_CHUNK = 256 * 1024
_STREAM_CAP = 400 * 1024 * 1024

# Container header signatures: R8b §2–3 and ClamAV's filetypes_int.h;
# RAR (rarlab), 7z (7-zip format), CAB (MS-CAB), OLE2/MSI (MS-CFB),
# PDF (ISO 32000). ZIP is excluded because core inventories its members.
_OPAQUE_MAGIC = (
    (b"Rar!\x1a\x07\x00", "RAR"), (b"Rar!\x1a\x07\x01\x00", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "SEVEN_Z"), (b"MSCF", "CAB"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2_MSI"),
    (b"%PDF-", "PDF"),
)


@dataclass(frozen=True)
class DatabaseFacts:
    """Facts supplied by the M6 inventory/configuration integration."""

    loaded: bool = False
    verified: bool = False
    expected_daily_version: str | None = None
    inventory_digest: str | None = None
    config_digest: str | None = None
    configuration_acceptable: bool = False
    oldest_database_date: datetime | None = None


@dataclass(frozen=True)
class ClamdReadiness:
    transport_ready: bool
    daemon_verified: bool
    database_loaded: bool
    database_verified: bool
    database_fresh: bool
    reload_confirmed: bool
    configuration_acceptable: bool
    engine_version: str | None
    daily_version: str | None
    database_date: datetime | None
    generation_digest: str | None
    code: str

    @property
    def trusted(self) -> bool:
        return all((self.transport_ready, self.daemon_verified, self.database_loaded,
                    self.database_verified, self.database_fresh, self.reload_confirmed,
                    self.configuration_acceptable))


class _Failure(Exception):
    def __init__(self, status: StageStatus, code: str) -> None:
        self.status, self.code = status, code
        super().__init__(code)


def _version(raw: str) -> tuple[str, str, datetime]:
    try:
        engine, daily, date_text = raw.rsplit("/", 2)
        if not engine.startswith("ClamAV ") or not daily.isdecimal():
            raise ValueError
        date = datetime.strptime(date_text, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        return engine, daily, date
    except ValueError as exc:
        raise _Failure(StageStatus.ERROR, "VERSION_FRAME") from exc


def _reply(connection: socket.socket, deadline_ns: int) -> str:
    data = bytearray()
    while True:
        remaining = (deadline_ns - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise _Failure(StageStatus.TIMEOUT, "DEADLINE")
        connection.settimeout(min(0.25, remaining))
        try:
            part = connection.recv(min(4096, _REPLY_CAP + 1 - len(data)))
        except socket.timeout as exc:
            raise _Failure(StageStatus.TIMEOUT, "SOCKET_TIMEOUT") from exc
        if not part:
            raise _Failure(StageStatus.ERROR, "REPLY_EOF")
        if b"\0" in part:
            before, after = part.split(b"\0", 1)
            if after or len(data) + len(before) > _REPLY_CAP:
                raise _Failure(StageStatus.ERROR, "REPLY_TRAILING_OR_LONG")
            data.extend(before)
            break
        data.extend(part)
        if len(data) > _REPLY_CAP:
            raise _Failure(StageStatus.ERROR, "REPLY_LONG")
    if not data:
        raise _Failure(StageStatus.ERROR, "REPLY_EMPTY")
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise _Failure(StageStatus.ERROR, "REPLY_UTF8") from exc


def _scan_reply(raw: str) -> tuple[str, str | None]:
    if raw == "stream: OK":
        return "OK", None
    if raw.startswith("stream: ") and raw.endswith(" FOUND"):
        name = raw[8:-6]
        if name and len(name) <= 512 and not any(ch in name for ch in "\r\n\0"):
            return "FOUND", name
    if raw == "INSTREAM size limit exceeded. ERROR" or (
        raw.endswith(" ERROR") and raw[:-6] and not any(ch in raw for ch in "\r\n\0")
    ):
        return "ERROR", raw
    raise _Failure(StageStatus.ERROR, "REPLY_FRAME")


class ClamdAdapter:
    engine_id = "clamav"
    reopens_path = False

    def __init__(self, host: str = "127.0.0.1", port: int = 3310, *,
                 expected_daemon: ExpectedDaemon | None = None,
                 verifier: Callable[[socket.socket], bool] | None = None,
                 facts: Callable[[], DatabaseFacts] | None = None,
                 now: Callable[[], datetime] | None = None,
                 max_database_age_days: int = 7, stream_cap: int = _STREAM_CAP,
                 pool_size: int = 2) -> None:
        if host != "127.0.0.1" or not 1 <= port <= 65535 or not 1 <= pool_size <= 3:
            raise ValueError("private IPv4 loopback and pool of 1–3 required")
        if max_database_age_days < 0 or stream_cap <= 0:
            raise ValueError("invalid limits")
        self.address = (host, port)
        self._verifier = verifier or (lambda conn: verify_connected_daemon(conn, expected_daemon))
        self._facts = facts or DatabaseFacts
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._age = max_database_age_days
        self._cap = stream_cap
        self._pool = threading.BoundedSemaphore(pool_size)
        self._state_lock = threading.Lock()
        self._reload_target: str | None = None
        self._reload_acknowledged = False

    def _connect(self, deadline_ns: int) -> socket.socket:
        remaining = (deadline_ns - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise _Failure(StageStatus.TIMEOUT, "DEADLINE")
        try:
            return socket.create_connection(self.address, timeout=min(0.25, remaining))
        except ConnectionRefusedError as exc:
            raise _Failure(StageStatus.UNAVAILABLE, "CONNECTION_REFUSED") from exc
        except socket.timeout as exc:
            raise _Failure(StageStatus.TIMEOUT, "SOCKET_TIMEOUT") from exc
        except OSError as exc:
            raise _Failure(StageStatus.UNAVAILABLE, "CONNECTION_ERROR") from exc

    def _command(self, command: bytes, deadline_ns: int) -> tuple[str, bool]:
        with self._connect(deadline_ns) as connection:
            try:
                verified = bool(self._verifier(connection))
            except Exception:
                verified = False
            connection.sendall(b"z" + command + b"\0")
            return _reply(connection, deadline_ns), verified

    def request_reload(self, new_daily_version: str, deadline_ns: int) -> bool:
        if not new_daily_version.isdecimal():
            raise ValueError("daily version must be numeric")
        with self._state_lock:
            self._reload_target = new_daily_version
            self._reload_acknowledged = False
        try:
            answer, verified = self._command(b"RELOAD", deadline_ns)
        except (OSError, _Failure):
            return False
        with self._state_lock:
            self._reload_acknowledged = answer == "RELOADING" and verified
            return self._reload_acknowledged

    def readiness(self, deadline_ns: int | None = None) -> ClamdReadiness:
        deadline_ns = deadline_ns or time.monotonic_ns() + 3_000_000_000
        try:
            pong, ping_owner = self._command(b"PING", deadline_ns)
            if pong != "PONG":
                raise _Failure(StageStatus.ERROR, "PING_FRAME")
            version, version_owner = self._command(b"VERSION", deadline_ns)
            engine, daily, db_date = _version(version)
            facts = self._facts()
            now = self._now()
            oldest = min((db_date, facts.oldest_database_date or db_date))
            fresh = 0 <= (now - oldest).total_seconds() <= self._age * 86400
            loaded = facts.loaded and bool(daily)
            verified_db = (facts.verified and bool(facts.inventory_digest) and
                           facts.expected_daily_version == daily)
            with self._state_lock:
                if self._reload_target is None:
                    reload_ok = True
                else:
                    reload_ok = self._reload_acknowledged and daily == self._reload_target
                    if reload_ok:
                        self._reload_target = None
                        self._reload_acknowledged = False
            config_ok = facts.configuration_acceptable and bool(facts.config_digest)
            generation = None
            if verified_db and config_ok:
                payload = json.dumps((daily, facts.inventory_digest, facts.config_digest),
                                     separators=(",", ":")).encode("utf-8")
                generation = hashlib.sha256(payload).hexdigest()
            owner = ping_owner and version_owner
            code = ("READY" if all((owner, loaded, verified_db, fresh, reload_ok, config_ok))
                    else "DAEMON_UNVERIFIED" if not owner else "DATABASE_UNLOADED" if not loaded
                    else "DATABASE_UNVERIFIED" if not verified_db else "DATABASE_STALE" if not fresh
                    else "RELOAD_PENDING" if not reload_ok else "CONFIGURATION_UNACCEPTABLE")
            return ClamdReadiness(True, owner, loaded, verified_db, fresh, reload_ok,
                                  config_ok, engine, daily, db_date, generation, code)
        except (_Failure, OSError, ValueError, TypeError) as exc:
            code = exc.code if isinstance(exc, _Failure) else "READINESS_ERROR"
            return ClamdReadiness(False, False, False, False, False, False, False,
                                  None, None, None, None, code)

    def scan_bound(self, request: ScanRequest, measured: FileIdentity,
                   cancel: CancellationToken, reader: BoundReader) -> EngineResult:
        start = time.monotonic_ns()
        ledger = CoverageLedger(measured.size)
        readiness = self.readiness(request.deadline_monotonic_ns)
        status = StageStatus.UNVERIFIED
        code = readiness.code
        evidence: tuple[Evidence, ...] = ()
        sent = 0
        acquired = False
        try:
            if not readiness.transport_ready:
                status = (StageStatus.TIMEOUT if code in ("DEADLINE", "SOCKET_TIMEOUT")
                          else StageStatus.UNAVAILABLE if code in ("CONNECTION_REFUSED", "CONNECTION_ERROR")
                          else StageStatus.ERROR)
                raise _Failure(status, code)
            while not acquired:
                if cancel.cancelled():
                    raise _Failure(StageStatus.CANCELLED, "CANCELLED")
                if time.monotonic_ns() >= request.deadline_monotonic_ns:
                    raise _Failure(StageStatus.TIMEOUT, "DEADLINE")
                acquired = self._pool.acquire(timeout=0.05)
            with self._connect(request.deadline_monotonic_ns) as connection:
                try:
                    scan_owner = bool(self._verifier(connection))
                except Exception:
                    scan_owner = False
                connection.sendall(b"zINSTREAM\0")
                first = b""
                size = min(measured.size, self._cap)
                while sent < size:
                    if cancel.cancelled():
                        raise _Failure(StageStatus.CANCELLED, "CANCELLED")
                    if time.monotonic_ns() >= request.deadline_monotonic_ns:
                        raise _Failure(StageStatus.TIMEOUT, "DEADLINE")
                    part = reader.read(sent, min(_CHUNK, reader.resident_limit, size - sent), cancel)
                    if not first:
                        first = part[:16]
                    connection.settimeout(min(0.25, max(0.001, (request.deadline_monotonic_ns - time.monotonic_ns()) / 1e9)))
                    connection.sendall(struct.pack(">I", len(part)) + part)
                    sent += len(part)
                connection.sendall(struct.pack(">I", 0))
                raw = _reply(connection, request.deadline_monotonic_ns)
            kind, name = _scan_reply(raw)
            trusted = readiness.trusted and scan_owner
            # F8: verified means only that these outer bytes reached the verified
            # daemon with an identified DB. It never certifies nested parsing.
            ledger.certainty = "verified" if trusted else "declared"
            ledger.inspected = (ByteRange(0, sent),) if sent else ()
            if measured.size > sent:
                ledger.fixed_reduction = True
            for magic, label in _OPAQUE_MAGIC:
                if first.startswith(magic):
                    ledger.child("opaque", f"OPAQUE_{label}")
                    break
            if kind == "ERROR":
                raise _Failure(StageStatus.ERROR, "CLAMD_ERROR")
            if kind == "FOUND" and name is not None:
                category, strength = classify_clamav_name(name)
                if strength is Strength.COVERAGE:
                    ledger.limit("CLAMD_COVERAGE_ALERT")
                if not trusted and strength is Strength.CONCLUSIVE:
                    strength = Strength.SUPPORTING
                evidence = (Evidence("clamav." + hashlib.sha256(name.encode()).hexdigest()[:24],
                                     self.engine_id, None, name, category, strength,
                                     "outer", None, (ByteRange(0, sent),) if sent else (),
                                     "clamav-active-db", readiness.generation_digest,
                                     None, trusted, "CLAMD_FOUND"),)
            status = (StageStatus.UNVERIFIED if not trusted else StageStatus.PARTIAL
                      if ledger.fixed_reduction or ledger.objects_opaque or ledger.limits_hit
                      else StageStatus.COMPLETED)
            code = readiness.code if not trusted else "READY"
        except ContentError as exc:
            status = StageStatus.CANCELLED if exc.code == "CANCELLED" else StageStatus.CHANGED if exc.code == "CHANGED" else StageStatus.ERROR
            code = exc.code
        except _Failure as exc:
            status, code = exc.status, exc.code
        except socket.timeout:
            status, code = StageStatus.TIMEOUT, "SOCKET_TIMEOUT"
        except OSError:
            status, code = StageStatus.ERROR, "SOCKET_ERROR"
        finally:
            if acquired:
                self._pool.release()
        if not ledger.inspected and sent:
            ledger.inspected = (ByteRange(0, sent),)
        coverage = ledger.finish()
        verdict = (VerdictCode.MALICIOUS if any(e.strength is Strength.CONCLUSIVE for e in evidence)
                   and status in (StageStatus.COMPLETED, StageStatus.PARTIAL) else
                   VerdictCode.SUSPICIOUS if evidence and status in (StageStatus.COMPLETED, StageStatus.PARTIAL) else
                   VerdictCode.CLEAN if status is StageStatus.COMPLETED else VerdictCode.UNKNOWN)
        error = (ScanError(code, "clamd", code, status in (StageStatus.ERROR, StageStatus.TIMEOUT,
                                                           StageStatus.UNAVAILABLE, StageStatus.CHANGED))
                 if status in (StageStatus.ERROR, StageStatus.TIMEOUT, StageStatus.UNAVAILABLE,
                               StageStatus.CHANGED) else None)
        return EngineResult(CONTRACT_VERSION, self.engine_id, request.file_id, measured,
                            status, verdict, coverage, evidence, readiness.engine_version,
                            readiness.daily_version, readiness.generation_digest, code,
                            start, (time.monotonic_ns() - start) // 1_000_000, error)
