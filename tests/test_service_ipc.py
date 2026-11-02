"""A1: service protocol, command authorization and ServiceCore (R13, R13b P3, P8).

Unelevated: the pipe DACL, service shell and token checks on a real machine
belong to the owner's elevated acceptance script.
"""

from __future__ import annotations

import io
import socket
import struct
import threading
from typing import Any

import pytest

from sentinel.service import core as service_core
from sentinel.service.authz import Caller
from sentinel.service.core import ServiceCore
from sentinel.service.protocol import MAX_FRAME, ProtocolError, read_frame, write_frame

USER = Caller("S-1-5-21-1-1001", 1, "medium", False)
OTHER_USER = Caller("S-1-5-21-1-1002", 2, "medium", False)
HELPER = Caller("S-1-5-21-1-1001", 1, "high", True)  # UAC consent helper, same session
HELPER_OTHER_SESSION = Caller("S-1-5-21-1-1001", 3, "high", True)
LOW = Caller("S-1-5-21-1-1001", 1, "low", False)
REMOTE = Caller("S-1-5-21-1-1001", 1, "medium", False, remote=True)


class FakeBackend:
    def __init__(self) -> None:
        self.readable: set[str] = {"C:\\Users\\u\\Downloads\\setup.exe"}
        self.submitted: list[tuple[str, str, str | None]] = []
        self.executed: list[tuple[str, dict[str, Any]]] = []
        self.protection_on = True
        self.fail_status = False

    def status(self) -> dict[str, Any]:
        if self.fail_status:
            raise RuntimeError("C:\\secret\\path engine said something")
        return {"realtime": self.protection_on}

    def check_url(self, url: str) -> dict[str, Any]:
        return {"verdict": "unknown"}

    def can_read(self, caller: Caller, path: str) -> bool:
        return path in self.readable

    def submit_scan(self, path: str, *, reason: str, url: str | None) -> str:
        self.submitted.append((path, reason, url))
        return f"job{len(self.submitted)}"

    def job(self, job_id: str) -> dict[str, Any] | None:
        return {"job_id": job_id, "state": "queued"}

    def cancel_job(self, job_id: str) -> bool:
        return True

    def describe_plan(self, kind: str, params: dict[str, Any]) -> str | None:
        if kind == "restore_quarantine" and params["quarantine_id"] != "q1":
            return None
        return {"disable_protection": "Tắt bảo vệ thời gian thực",
                "trust_host": f"Luôn tin cậy {params.get('host')}"}.get(kind, kind)

    def execute_plan(self, kind: str, params: dict[str, Any]) -> dict[str, Any]:
        self.executed.append((kind, params))
        if kind == "disable_protection":
            self.protection_on = False
        return {"done": True}


class Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def svc():
    backend, clock = FakeBackend(), Clock()
    return ServiceCore(backend, clock=clock), backend, clock


def call(core: ServiceCore, caller: Caller, op: str, rid: int = 1, **args: Any) -> dict[str, Any]:
    return core.handle(caller, {"v": 1, "id": rid, "op": op, "args": args})


def code(resp: dict[str, Any]) -> str | None:
    return None if resp["ok"] else resp["error"]["code"]


# -- framing


def test_frames_round_trip_and_end_cleanly():
    buf = io.BytesIO()
    write_frame(buf, {"v": 1, "id": 7, "op": "hello"})
    buf.seek(0)
    assert read_frame(buf) == {"v": 1, "id": 7, "op": "hello"}
    assert read_frame(buf) is None


@pytest.mark.parametrize("raw,expected", [
    (struct.pack("<I", MAX_FRAME + 1), "TOO_LARGE"),
    (struct.pack("<I", 10) + b"{}", "BAD_FRAME"),
    (struct.pack("<I", 2) + b"[]", "BAD_FRAME"),
    (struct.pack("<I", 2) + b"\xff\xfe", "BAD_FRAME"),
])
def test_bad_frames_are_rejected(raw, expected):
    with pytest.raises(ProtocolError) as e:
        read_frame(io.BytesIO(raw))
    assert e.value.code == expected


@pytest.mark.parametrize("frame,expected", [
    ({"v": 2, "id": 1, "op": "hello"}, "BAD_VERSION"),
    ({"v": 1, "id": "1", "op": "hello"}, "BAD_REQUEST"),
    ({"v": 1, "id": True, "op": "hello"}, "BAD_REQUEST"),
    ({"v": 1, "id": 1, "op": "format_disk"}, "UNKNOWN_OP"),
    ({"v": 1, "id": 1, "op": "scan_request", "args": {"path": "C:\\a", "force": True}}, "BAD_REQUEST"),
    ({"v": 1, "id": 1, "op": "check_url", "args": {"url": "x" * 9000}}, "BAD_REQUEST"),
    ({"v": 1, "id": 1, "op": "check_url", "args": {"url": "http://a\x00b"}}, "BAD_REQUEST"),
    ({"v": 1, "id": 1, "op": "request_plan", "args": {"kind": "format_disk"}}, "BAD_REQUEST"),
])
def test_malformed_requests_are_refused(svc, frame, expected):
    core, _, _ = svc
    assert code(core.handle(USER, frame)) == expected


# -- authorization (R13b P3)


def test_low_integrity_and_remote_callers_get_nothing(svc):
    core, _, _ = svc
    assert code(call(core, LOW, "hello")) == "FORBIDDEN"
    assert code(call(core, REMOTE, "status")) == "FORBIDDEN"


def test_user_level_malware_cannot_switch_protection_off(svc):
    core, backend, _ = svc
    # Same token as the tray: it may ask...
    plan = call(core, USER, "request_plan", kind="disable_protection", params={})
    assert plan["ok"]
    pid = plan["result"]["plan_id"]
    # ...but neither read nor approve the plan without an elevated token.
    assert code(call(core, USER, "get_plan", plan_id=pid)) == "ELEVATION_REQUIRED"
    assert code(call(core, USER, "approve_plan", plan_id=pid, version=1)) == "ELEVATION_REQUIRED"
    high_not_admin = Caller(USER.sid, 1, "high", False)
    assert code(call(core, high_not_admin, "approve_plan", plan_id=pid, version=1)) == "ELEVATION_REQUIRED"
    assert backend.executed == [] and backend.protection_on


def test_elevated_helper_approves_exactly_what_the_service_shows_once(svc):
    core, backend, _ = svc
    pid = call(core, USER, "request_plan", kind="trust_host", params={"host": "example.test"})["result"]["plan_id"]
    shown = call(core, HELPER, "get_plan", plan_id=pid)["result"]
    assert shown["summary"] == "Luôn tin cậy example.test" and shown["version"] == 1
    assert code(call(core, HELPER, "approve_plan", plan_id=pid, version=2)) == "STALE_PLAN"
    assert call(core, HELPER, "approve_plan", plan_id=pid, version=1)["ok"]
    assert backend.executed == [("trust_host", {"host": "example.test"})]
    # Replay of the same approval finds nothing.
    assert code(call(core, HELPER, "approve_plan", plan_id=pid, version=1)) == "NOT_FOUND"
    assert len(backend.executed) == 1


def test_plans_expire_and_are_bound_to_the_session(svc):
    core, backend, clock = svc
    pid = call(core, USER, "request_plan", kind="disable_protection", params={})["result"]["plan_id"]
    assert code(call(core, HELPER_OTHER_SESSION, "approve_plan", plan_id=pid, version=1)) == "NOT_FOUND"
    clock.t += service_core.PLAN_TTL_SECONDS + 1
    assert code(call(core, HELPER, "approve_plan", plan_id=pid, version=1)) == "NOT_FOUND"
    assert backend.executed == []


def test_plan_for_a_missing_target_is_refused_and_plans_are_capped(svc):
    core, _, _ = svc
    assert code(call(core, USER, "request_plan", kind="restore_quarantine", params={"quarantine_id": "nope"})) == "NOT_FOUND"
    for i in range(service_core.MAX_PLANS_PER_CALLER):
        assert call(core, USER, "request_plan", rid=i, kind="disable_protection", params={})["ok"]
    assert code(call(core, USER, "request_plan", kind="disable_protection", params={})) == "BUSY"


# -- scans and download hints


@pytest.mark.parametrize("path", ["setup.exe", "\\\\server\\share\\a.exe", "\\\\?\\C:\\a.exe", "\\\\.\\PhysicalDrive0", "/etc/passwd"])
def test_only_absolute_local_paths_are_accepted(svc, path):
    core, backend, _ = svc
    assert code(call(core, USER, "scan_request", path=path)) == "BAD_PATH"
    assert backend.submitted == []


def test_a_user_cannot_have_the_service_scan_a_file_they_cannot_read(svc):
    core, backend, _ = svc
    assert code(call(core, USER, "scan_request", path="C:\\Users\\other\\secret.docx")) == "ACCESS_DENIED"
    assert backend.submitted == []


def test_download_hint_is_accepted_for_scanning_not_reported_as_scanned(svc):
    core, backend, _ = svc
    r = call(core, USER, "download_hint", path="C:\\Users\\u\\Downloads\\setup.exe", url="https://example.test/f", download_id=5)
    assert r["ok"] and r["result"] == {"job_id": "job1", "accepted": True}
    assert backend.submitted == [("C:\\Users\\u\\Downloads\\setup.exe", "download", "https://example.test/f")]


def test_jobs_belong_to_their_caller(svc):
    core, _, _ = svc
    jid = call(core, USER, "scan_request", path="C:\\Users\\u\\Downloads\\setup.exe")["result"]["job_id"]
    assert call(core, USER, "job_status", job_id=jid)["ok"]
    assert code(call(core, OTHER_USER, "job_status", job_id=jid)) == "NOT_FOUND"
    assert code(call(core, OTHER_USER, "cancel_job", job_id=jid)) == "NOT_FOUND"


def test_queued_scans_per_caller_are_capped(svc, monkeypatch):
    core, _, _ = svc
    monkeypatch.setattr(service_core, "MAX_JOBS_PER_CALLER", 3)
    for i in range(3):
        assert call(core, USER, "scan_request", rid=i, path="C:\\Users\\u\\Downloads\\setup.exe")["ok"]
    assert code(call(core, USER, "scan_request", path="C:\\Users\\u\\Downloads\\setup.exe")) == "BUSY"


# -- robustness


def test_rate_limit_per_caller_refills_over_time(svc):
    core, _, clock = svc
    answers = [code(call(core, USER, "hello", rid=i)) for i in range(int(service_core.RATE_CAPACITY) + 1)]
    assert answers[-1] == "RATE_LIMITED" and answers[0] is None
    assert call(core, OTHER_USER, "hello")["ok"], "one noisy caller does not starve another"
    clock.t += 1.0
    assert call(core, USER, "hello")["ok"]


def test_stopping_refuses_new_work_but_answers_status(svc):
    core, backend, _ = svc
    core.stop()
    assert code(call(core, USER, "scan_request", path="C:\\Users\\u\\Downloads\\setup.exe")) == "STOPPING"
    assert call(core, USER, "status")["ok"]
    assert backend.submitted == []


def test_backend_errors_do_not_leak_details(svc):
    core, backend, _ = svc
    backend.fail_status = True
    r = call(core, USER, "status")
    assert code(r) == "INTERNAL" and "secret" not in str(r)


def test_serve_over_a_stream_pair():
    backend = FakeBackend()
    core = ServiceCore(backend)
    server_sock, client_sock = socket.socketpair()
    s_in, s_out = server_sock.makefile("rb"), server_sock.makefile("wb")
    out, inp = client_sock.makefile("wb"), client_sock.makefile("rb")
    # Daemon, and every file object closed in finally: a failing assertion
    # must not leave the server blocked on a socket that never reaches EOF.
    server = threading.Thread(target=core.serve, args=(USER, s_in, s_out), daemon=True)
    server.start()
    try:
        write_frame(out, {"v": 1, "id": 1, "op": "hello"})
        write_frame(out, {"v": 1, "id": 2, "op": "approve_plan", "args": {"plan_id": "x", "version": 1}})
        first, second = read_frame(inp), read_frame(inp)
        assert first["ok"] and first["result"]["elevated_caller"] is False
        assert second["error"]["code"] == "ELEVATION_REQUIRED"
        out.write(struct.pack("<I", MAX_FRAME + 1))
        out.flush()
        assert read_frame(inp)["error"]["code"] == "TOO_LARGE"
    finally:
        # Client side first, so the server reads end of stream and returns.
        for f in (out, inp):
            try:
                f.close()
            except OSError:
                pass
        client_sock.close()
        server.join(5)
        s_in.close()
        s_out.close()
        server_sock.close()
    assert not server.is_alive()
