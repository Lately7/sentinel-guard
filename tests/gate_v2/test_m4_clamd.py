"""Harmless loopback protocol and policy checks for the ClamAV adapter."""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.gate_v2.clamd import ClamdAdapter, DatabaseFacts
from sentinel.gate_v2.contract import ActionCode, ScanRequest, StageStatus, Strength, VerdictCode
from sentinel.gate_v2.orchestrator import scan
from sentinel.gate_v2.winnet import connected_server_pid

NOW = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)
VERSION_1 = b"ClamAV 1.4.3/27650/Mon Nov  2 12:00:00 2026\0"
VERSION_2 = b"ClamAV 1.4.3/27651/Mon Nov  2 12:00:00 2026\0"


class FakeClamd:
    def __init__(self, reply: bytes = b"stream: OK\0", *, delay: float = 0,
                 reload_reply: bytes = b"RELOADING\0") -> None:
        self.reply = reply
        self.delay = delay
        self.reload_reply = reload_reply
        self.version = VERSION_1
        self.streams: list[bytes] = []
        self.commands: list[bytes] = []
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self._run, daemon=True)
        self.worker.start()

    def _run(self) -> None:
        while not self.stop.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(1)
                try:
                    command = self._until(connection, b"\0")
                    self.commands.append(command)
                    if command == b"zPING\0":
                        answer = b"PONG\0"
                    elif command == b"zVERSION\0":
                        answer = self.version
                    elif command == b"zRELOAD\0":
                        answer = self.reload_reply
                    elif command == b"zINSTREAM\0":
                        body = bytearray()
                        while True:
                            length = struct.unpack(">I", self._exact(connection, 4))[0]
                            if length == 0:
                                break
                            body.extend(self._exact(connection, length))
                        self.streams.append(bytes(body))
                        answer = self.reply
                    else:
                        answer = b"UNKNOWN COMMAND\0"
                    if self.delay and command == b"zINSTREAM\0":
                        time.sleep(self.delay)
                    connection.sendall(answer)
                except (OSError, ValueError, struct.error):
                    pass

    @staticmethod
    def _exact(connection: socket.socket, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            part = connection.recv(size - len(data))
            if not part:
                raise ValueError("truncated fake request")
            data.extend(part)
        return bytes(data)

    @classmethod
    def _until(cls, connection: socket.socket, marker: bytes) -> bytes:
        data = bytearray()
        while not data.endswith(marker):
            data.extend(cls._exact(connection, 1))
        return bytes(data)

    def close(self) -> None:
        self.stop.set()
        self.socket.close()
        self.worker.join(timeout=2)

    def __enter__(self) -> FakeClamd:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def facts(daily: str = "27650", *, fresh: bool = True, acceptable: bool = True,
          digest: str = "a" * 64) -> DatabaseFacts:
    return DatabaseFacts(True, True, daily, digest, "b" * 64, acceptable,
                         NOW - timedelta(days=1 if fresh else 8))


def adapter(port: int, *, verified: bool = True, db_facts: DatabaseFacts | None = None,
            cap: int = 400 * 1024 * 1024) -> ClamdAdapter:
    return ClamdAdapter(port=port, verifier=lambda _: verified,
                        facts=lambda: db_facts or facts(), now=lambda: NOW,
                        stream_cap=cap)


def decision(engine: ClamdAdapter, data: bytes = b"harmless bytes", *,
             timeout: float = 3, cancel: object = None):
    request = ScanRequest(2, "m4", "file", None, data, "test", "memory",
                          "evidence-v1", "evidence-v1",
                          time.monotonic_ns() + int(timeout * 1e9), None, False)
    return scan(request, adapters=[engine], cancel=cancel,
                gate_generation="m4", auto_quarantine=True)


@pytest.mark.parametrize("reply,status,strength,verdict", [
    (b"stream: OK\0", StageStatus.COMPLETED, None, VerdictCode.CLEAN),
    (b"stream: Win.Trojan.Test FOUND\0", StageStatus.COMPLETED, Strength.CONCLUSIVE, VerdictCode.MALICIOUS),
    (b"stream: PUA.Test FOUND\0", StageStatus.COMPLETED, Strength.SUPPORTING, VerdictCode.SUSPICIOUS),
    (b"stream: Heuristics.Test FOUND\0", StageStatus.COMPLETED, Strength.SUPPORTING, VerdictCode.SUSPICIOUS),
    (b"stream: BC.Heuristics.Test FOUND\0", StageStatus.COMPLETED, Strength.SUPPORTING, VerdictCode.SUSPICIOUS),
    (b"stream: Win.Trojan.Suspect-34 FOUND\0", StageStatus.COMPLETED, Strength.SUPPORTING, VerdictCode.SUSPICIOUS),
    (b"stream: Heuristics.Limits.Exceeded.Size FOUND\0", StageStatus.PARTIAL, Strength.COVERAGE, VerdictCode.UNKNOWN),
    (b"stream: Heuristics.Encrypted.Zip FOUND\0", StageStatus.PARTIAL, Strength.COVERAGE, VerdictCode.UNKNOWN),
    (b"stream: scan failed ERROR\0", StageStatus.ERROR, None, VerdictCode.UNKNOWN),
    (b"INSTREAM size limit exceeded. ERROR\0", StageStatus.ERROR, None, VerdictCode.UNKNOWN),
    (b"\0", StageStatus.ERROR, None, VerdictCode.UNKNOWN),
    (b"path: Win.Test FOUND\0", StageStatus.ERROR, None, VerdictCode.UNKNOWN),
    (b"stream: OK", StageStatus.ERROR, None, VerdictCode.UNKNOWN),
    (b"x" * 4097 + b"\0", StageStatus.ERROR, None, VerdictCode.UNKNOWN),
    (b"stream: OK\0garbage", StageStatus.ERROR, None, VerdictCode.UNKNOWN),
])
def test_fake_reply_matrix(reply: bytes, status: StageStatus,
                           strength: Strength | None, verdict: VerdictCode) -> None:
    with FakeClamd(reply) as daemon:
        result = decision(adapter(daemon.port))
        stage = result.engine_results[0]
        assert stage.status is status
        assert result.verdict is verdict
        assert (stage.evidence[0].strength if stage.evidence else None) is strength
        assert daemon.streams == [b"harmless bytes"]
        if reply.startswith(b"stream: Win.Trojan.Test"):
            assert stage.evidence[0].raw_name == "Win.Trojan.Test"
            assert stage.evidence[0].source_digest == stage.generation_digest
            # These bytes are in memory: there is no file to quarantine (R15-12).
            assert result.action_decision.action is ActionCode.NOTIFY
        if status is StageStatus.COMPLETED and not stage.evidence:
            assert result.trusted_clean
        if status in (StageStatus.ERROR, StageStatus.PARTIAL):
            assert not result.trusted_clean


def test_unverified_daemon_found_is_notify_only() -> None:
    with FakeClamd(b"stream: Win.Trojan.Test FOUND\0") as daemon:
        result = decision(adapter(daemon.port, verified=False))
    stage = result.engine_results[0]
    assert stage.status is StageStatus.UNVERIFIED
    assert stage.evidence[0].verified is False
    assert stage.evidence[0].strength is Strength.SUPPORTING
    assert result.verdict is VerdictCode.UNKNOWN
    assert "UNACCEPTED_DETECTION" in result.reason_codes
    assert result.action_decision.action is ActionCode.NOTIFY
    assert result.action_decision.reason_code == "UNVERIFIED_CLAMD"


def test_reload_old_then_new_daily_generation() -> None:
    with FakeClamd() as daemon:
        current = {"facts": facts()}
        engine = ClamdAdapter(port=daemon.port, verifier=lambda _: True,
                              facts=lambda: current["facts"], now=lambda: NOW)
        before = engine.readiness()
        assert before.trusted
        assert engine.request_reload("27651", time.monotonic_ns() + 2_000_000_000)
        old = decision(engine)
        assert old.engine_results[0].status is StageStatus.UNVERIFIED
        assert old.engine_results[0].readiness_code == "RELOAD_PENDING"
        assert not old.trusted_clean
        daemon.version = VERSION_2
        current["facts"] = facts("27651")
        new = decision(engine)
        assert new.engine_results[0].status is StageStatus.COMPLETED
        assert new.trusted_clean
        assert new.engine_results[0].generation_digest != before.generation_digest


def test_stale_or_unverified_database_and_config() -> None:
    with FakeClamd() as daemon:
        for db_facts, code in ((facts(fresh=False), "DATABASE_STALE"),
                               (facts(daily="1"), "DATABASE_UNVERIFIED"),
                               (facts(acceptable=False), "CONFIGURATION_UNACCEPTABLE")):
            result = decision(adapter(daemon.port, db_facts=db_facts))
            assert result.engine_results[0].status is StageStatus.UNVERIFIED
            assert result.engine_results[0].readiness_code == code
            assert result.verdict is VerdictCode.UNKNOWN
            assert not result.trusted_clean


@pytest.mark.parametrize("header,reason", [
    (b"Rar!\x1a\x07\x00", "OPAQUE_RAR"),
    (b"7z\xbc\xaf\x27\x1c", "OPAQUE_SEVEN_Z"),
    (b"MSCF", "OPAQUE_CAB"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OPAQUE_OLE2_MSI"),
    (b"%PDF-", "OPAQUE_PDF"),
])
def test_opaque_container_ok_is_not_trusted_clean(header: bytes, reason: str) -> None:
    with FakeClamd() as daemon:
        result = decision(adapter(daemon.port), header + b" harmless")
    stage = result.engine_results[0]
    assert stage.status is StageStatus.PARTIAL
    assert stage.coverage.object_reasons == (reason,)
    assert stage.coverage.objects_inspected == 0
    assert result.verdict is VerdictCode.UNKNOWN
    assert not result.trusted_clean


def test_stream_cap_and_digest_content() -> None:
    with FakeClamd() as daemon:
        first = decision(adapter(daemon.port, cap=4), b"abcdefgh")
        second = decision(adapter(daemon.port, db_facts=facts(digest="c" * 64)), b"abcdefgh")
        assert daemon.streams == [b"abcd", b"abcdefgh"]
        assert first.engine_results[0].status is StageStatus.PARTIAL
        assert first.engine_results[0].coverage.inspected[0].end == 4
        assert first.policy_scope == "reduced"
        assert first.engine_results[0].generation_digest != second.engine_results[0].generation_digest


def test_timeout_and_refusal() -> None:
    with FakeClamd(delay=0.5) as daemon:
        timed = decision(adapter(daemon.port), timeout=0.1)
    assert timed.engine_results[0].status is StageStatus.TIMEOUT
    assert timed.verdict is VerdictCode.UNKNOWN
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    refused = decision(adapter(port))
    assert refused.engine_results[0].status is StageStatus.UNAVAILABLE
    assert refused.verdict is VerdictCode.UNKNOWN


def test_delayed_instream_reply_completes() -> None:
    with FakeClamd(delay=1.0) as daemon:
        result = decision(adapter(daemon.port), timeout=3)
    assert result.engine_results[0].status is StageStatus.COMPLETED
    assert result.trusted_clean


def test_instream_waits_until_deadline() -> None:
    with FakeClamd(delay=1.5) as daemon:
        started = time.monotonic()
        result = decision(adapter(daemon.port), timeout=0.7)
        elapsed = time.monotonic() - started
    assert result.engine_results[0].status is StageStatus.TIMEOUT
    assert 0.55 <= elapsed < 1.3


def test_cancel_during_instream_reply_wait() -> None:
    stopped = threading.Event()

    class Token:
        def cancelled(self) -> bool:
            return stopped.is_set()

    with FakeClamd(delay=1.0) as daemon:
        timer = threading.Timer(0.35, stopped.set)
        timer.start()
        started = time.monotonic()
        result = decision(adapter(daemon.port), timeout=3, cancel=Token())
        elapsed = time.monotonic() - started
        timer.join()
    assert result.engine_results[0].status is StageStatus.CANCELLED
    assert elapsed < 0.7


def test_readiness_cache_reused_and_invalidated_after_error() -> None:
    with FakeClamd() as daemon:
        engine = adapter(daemon.port)
        for _ in range(3):
            assert decision(engine).engine_results[0].status is StageStatus.COMPLETED
        assert daemon.commands.count(b"zPING\0") == 1
        assert daemon.commands.count(b"zVERSION\0") == 1
        daemon.reply = b"bad reply\0"
        assert decision(engine).engine_results[0].status is StageStatus.ERROR
        daemon.reply = b"stream: OK\0"
        assert decision(engine).engine_results[0].status is StageStatus.COMPLETED
        assert daemon.commands.count(b"zPING\0") == 2
        assert daemon.commands.count(b"zVERSION\0") == 2


def test_failed_reload_keeps_old_generation_active() -> None:
    with FakeClamd(reload_reply=b"UNKNOWN COMMAND\0") as daemon:
        engine = adapter(daemon.port)
        before = engine.readiness()
        assert not engine.request_reload("27651", time.monotonic_ns() + 2_000_000_000)
        after = engine.readiness()
        assert after.code == "RELOAD_FAILED"
        assert after.trusted
        assert after.generation_digest == before.generation_digest
        result = decision(engine)
        assert result.engine_results[0].status is StageStatus.COMPLETED
        assert result.engine_results[0].readiness_code == "RELOAD_FAILED"


def test_reload_activation_window_expires_to_old_generation() -> None:
    with FakeClamd() as daemon:
        tick = [time.monotonic_ns()]
        engine = ClamdAdapter(port=daemon.port, verifier=lambda _: True,
                              facts=facts, now=lambda: NOW, clock_ns=lambda: tick[0],
                              reload_window_seconds=2)
        before = engine.readiness()
        assert engine.request_reload("27651", time.monotonic_ns() + 2_000_000_000)
        assert engine.readiness().code == "RELOAD_PENDING"
        tick[0] += 3_000_000_000
        after = engine.readiness()
        assert after.code == "RELOAD_FAILED"
        assert after.trusted
        assert after.generation_digest == before.generation_digest


@pytest.mark.skipif(os.name != "nt", reason="Windows TCP owner table")
def test_windows_owner_table_finds_fake_server_pid() -> None:
    with FakeClamd() as daemon:
        with socket.create_connection(("127.0.0.1", daemon.port)) as connection:
            assert connected_server_pid(connection) == os.getpid()
