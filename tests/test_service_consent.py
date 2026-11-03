"""A3 confirmation is service text only and an explicit Yes click."""

from __future__ import annotations

import pytest

from sentinel.service.authz import Caller
from sentinel.service.consent import ConsentError, TITLE, confirm, validate_plan_id
from sentinel.service.core import PLAN_TTL_SECONDS, ServiceCore

from test_service_ipc import Clock, FakeBackend, HELPER, USER, call


PLAN = "a" * 32


class FakeClient:
    def __init__(self, plan=None):
        self.plan = plan or {"plan_id": PLAN, "version": 1, "summary": "Xóa mục thử nghiệm"}
        self.calls = []

    def request(self, op, **kwargs):
        self.calls.append((op, kwargs))
        return self.plan if op == "get_plan" else {"done": True}


def test_plan_id_is_fixed_length_hex():
    assert validate_plan_id(PLAN) == PLAN
    for bad in ("", "abc", "g" * 32, "A" * 32, "a" * 32 + " --text=evil"):
        with pytest.raises(ConsentError):
            validate_plan_id(bad)


def test_dialog_uses_only_service_text_and_no_yes_default():
    client = FakeClient()
    shown = []
    assert confirm(PLAN, client=client, message_box=lambda *args: (shown.append(args), 6)[1])
    assert shown == [(None, "Xóa mục thử nghiệm", TITLE, 0x134)]
    assert client.calls == [("get_plan", {"plan_id": PLAN}),
                            ("approve_plan", {"plan_id": PLAN, "version": 1})]


def test_dialog_cancel_does_not_approve():
    client = FakeClient()
    assert not confirm(PLAN, client=client, message_box=lambda *args: 7)
    assert [op for op, _ in client.calls] == ["get_plan"]


def test_changed_plan_reference_refused_before_display():
    client = FakeClient({"plan_id": "b" * 32, "version": 1, "summary": "other"})
    with pytest.raises(ConsentError, match="BAD_PLAN"):
        confirm(PLAN, client=client, message_box=lambda *args: 6)


def test_the_tray_finds_the_helper_through_the_service_registration(tmp_path, monkeypatch):
    from sentinel.service import consent
    from sentinel.service.paths import installed_paths

    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    paths.version.mkdir(parents=True)
    (paths.version / "pythonw.exe").write_bytes(b"stand-in")
    monkeypatch.setattr(consent, "installed_paths", lambda version: paths)
    monkeypatch.setattr(consent, "active_version", lambda: None)
    monkeypatch.setattr(consent, "registered_version", lambda: None)
    with pytest.raises(ConsentError, match="INSTALL_INTEGRITY"):
        consent.protected_helper()
    monkeypatch.setattr(consent, "registered_version", lambda: paths.version)
    assert consent.protected_helper() == (paths.version / "pythonw.exe", paths.version)


def test_service_claim_expiry_and_changed_target():
    backend, clock = FakeBackend(), Clock()
    core = ServiceCore(backend, clock=clock)
    pid = call(core, USER, "request_plan", kind="trust_host", params={"host": "example.test"})["result"]["plan_id"]
    assert call(core, HELPER, "get_plan", plan_id=pid)["ok"]
    assert call(core, HELPER, "get_plan", plan_id=pid)["error"]["code"] == "PLAN_CLAIMED"
    backend.describe_plan = lambda kind, params: "Mục tiêu đã đổi"
    assert call(core, HELPER, "approve_plan", plan_id=pid, version=1)["error"]["code"] == "STALE_PLAN"
    assert backend.executed == []
    clock.t += PLAN_TTL_SECONDS - 1
    assert call(core, HELPER, "approve_plan", plan_id=pid, version=1)["error"]["code"] == "STALE_PLAN"
    clock.t += 2
    assert call(core, HELPER, "approve_plan", plan_id=pid, version=1)["error"]["code"] == "NOT_FOUND"


def test_other_admin_sid_cannot_claim_requester_plan():
    core = ServiceCore(FakeBackend())
    pid = call(core, USER, "request_plan", kind="disable_protection", params={})["result"]["plan_id"]
    another_admin = Caller("S-1-5-21-other", USER.session_id, "high", True)
    assert call(core, another_admin, "get_plan", plan_id=pid)["error"]["code"] == "REQUESTER_MISMATCH"


def test_claim_is_bound_to_elevated_pipe_connection():
    core = ServiceCore(FakeBackend())
    pid = call(core, USER, "request_plan", kind="disable_protection", params={})["result"]["plan_id"]
    frame = lambda op: {"v": 1, "id": 1, "op": op,
                        "args": {"plan_id": pid, **({"version": 1} if op == "approve_plan" else {})}}
    assert core.handle(HELPER, frame("get_plan"), connection_id="first")["ok"]
    assert core.handle(HELPER, frame("get_plan"), connection_id="second")["error"]["code"] == "PLAN_CLAIMED"
    assert core.handle(HELPER, frame("approve_plan"), connection_id="second")["error"]["code"] == "PLAN_CLAIMED"
    assert core.handle(HELPER, frame("approve_plan"), connection_id="first")["ok"]


def test_unclaimed_plan_cannot_be_approved():
    backend = FakeBackend()
    core = ServiceCore(backend)
    pid = call(core, USER, "request_plan", kind="disable_protection", params={})["result"]["plan_id"]
    assert call(core, HELPER, "approve_plan", plan_id=pid, version=1)["error"]["code"] == "PLAN_CLAIMED"
    assert backend.executed == []
    assert call(core, HELPER, "get_plan", plan_id=pid)["ok"]
    assert call(core, HELPER, "approve_plan", plan_id=pid, version=1)["ok"]
