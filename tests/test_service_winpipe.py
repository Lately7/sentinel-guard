"""A1: the real Windows named-pipe transport, unelevated and same-user.

The service DACL (SYSTEM/Administrators/Interactive users), LocalSystem
identity and cross-user denial are checked by the owner's elevated acceptance
script, not here.
"""

from __future__ import annotations

import os
import struct
import threading
import uuid

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="named pipes need Windows")

from sentinel.service.core import ServiceCore  # noqa: E402
from sentinel.service.protocol import MAX_FRAME, read_frame, write_frame  # noqa: E402

from test_service_ipc import FakeBackend  # noqa: E402


@pytest.fixture
def server():
    from sentinel.service import winpipe

    me = winpipe.current_process_caller()
    name = rf"\\.\pipe\SentinelGuardTest-{uuid.uuid4().hex}"
    core = ServiceCore(FakeBackend())
    srv = winpipe.PipeServer(core, name=name, sddl=f"D:P(A;;GA;;;{me.sid})")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield winpipe, srv, name, me
    srv.stop()
    t.join(5)
    assert not t.is_alive(), "stop() must end the accept loop"


def ask(winpipe, name, *frames):
    conn = winpipe.connect(name)
    try:
        answers = []
        for f in frames:
            write_frame(conn, f)
            answers.append(read_frame(conn))
        return answers
    finally:
        conn.close()


def test_caller_identity_comes_from_the_client_token(server):
    winpipe, srv, name, me = server
    assert me.sid.startswith("S-1-5-") and me.integrity in ("medium", "high", "system")
    seen = []
    real = srv.core.handle
    srv.core.handle = lambda caller, frame: (seen.append(caller), real(caller, frame))[1]
    [hello] = ask(winpipe, name, {"v": 1, "id": 1, "op": "hello"})
    assert hello["ok"]
    assert [(c.sid, c.session_id, c.integrity, c.is_admin, c.remote) for c in seen] == [
        (me.sid, me.session_id, me.integrity, me.is_admin, False)]
    assert hello["result"]["elevated_caller"] == (me.is_admin and me.integrity in ("high", "system"))


def test_unelevated_client_cannot_approve_over_the_real_pipe(server):
    winpipe, _srv, name, me = server
    if me.is_admin:
        pytest.skip("test runner is elevated; the owner's acceptance script covers this case")
    plan, approve = ask(winpipe, name,
                        {"v": 1, "id": 1, "op": "request_plan", "args": {"kind": "disable_protection", "params": {}}},
                        {"v": 1, "id": 2, "op": "approve_plan", "args": {"plan_id": "0" * 32, "version": 1}})
    assert plan["ok"]
    assert approve["error"]["code"] == "ELEVATION_REQUIRED"


def test_oversized_frame_ends_the_connection(server):
    winpipe, _srv, name, _me = server
    conn = winpipe.connect(name)
    try:
        conn.write(struct.pack("<I", MAX_FRAME + 1))
        assert read_frame(conn)["error"]["code"] == "TOO_LARGE"
        assert conn.read(4) == b"", "server closed the connection"
    finally:
        conn.close()


def test_a_squatted_pipe_name_stops_the_server_from_starting():
    from sentinel.service import winpipe

    me = winpipe.current_process_caller()
    name = rf"\\.\pipe\SentinelGuardTest-{uuid.uuid4().hex}"
    first = winpipe.PipeServer(ServiceCore(FakeBackend()), name=name, sddl=f"D:P(A;;GA;;;{me.sid})")
    try:
        # Someone else already owns the name: FILE_FLAG_FIRST_PIPE_INSTANCE
        # makes the real service refuse to start instead of sharing it.
        with pytest.raises(winpipe.PipeError):
            winpipe.PipeServer(ServiceCore(FakeBackend()), name=name, sddl=f"D:P(A;;GA;;;{me.sid})")
    finally:
        winpipe._k32.CloseHandle(first._pending)


def test_client_round_trip_and_typed_errors(server):
    from sentinel.service.client import ServiceClient, ServiceError, ServiceUnavailable

    _winpipe, _srv, name, me = server
    with ServiceClient(name) as c:
        assert c.request("hello")["protocol"] == 1
        assert c.request("status") == {"realtime": True}
        with pytest.raises(ServiceError) as e:
            c.request("approve_plan", plan_id="0" * 32, version=1)
        assert e.value.code == ("NOT_FOUND" if me.is_admin else "ELEVATION_REQUIRED")
        assert c.request("hello")["protocol"] == 1, "the connection survives a refused request"
    with pytest.raises(ServiceUnavailable):
        ServiceClient(rf"\\.\pipe\SentinelGuardTest-missing-{uuid.uuid4().hex}").request("hello")
