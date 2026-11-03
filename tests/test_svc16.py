"""Regressions for approval results and browser trust synchronization."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from sentinel.db import Database
from sentinel.nativehost import BadRequest, Host
from sentinel.service import consent
from sentinel.service.bridge import ApprovalResult, ServiceLease
from sentinel.service.client import ServiceError, ServiceUnavailable
from sentinel.service.core import PLAN_TTL_SECONDS
from sentinel.service.core import ServiceCore
from test_service_ipc import FakeBackend, USER, call


ROOT = Path(__file__).resolve().parents[1]


def test_plan_and_helper_wait_cover_five_minutes() -> None:
    assert PLAN_TTL_SECONDS == 300
    assert consent.launch_consent.__kwdefaults__["timeout_ms"] == 300_000


@pytest.mark.parametrize(("helper", "expected"), [
    (lambda: False, "CANCELLED"),
    (lambda: (_ for _ in ()).throw(consent.ConsentError("DECLINED")), "DECLINED"),
    (lambda: (_ for _ in ()).throw(consent.ConsentError("EXPIRED")), "EXPIRED"),
    (lambda: (_ for _ in ()).throw(consent.ConsentError("HELPER_FAILED")), "HELPER_FAILED"),
])
def test_approval_result_preserves_failure_reason_and_false_truth(monkeypatch, helper, expected: str) -> None:
    monkeypatch.setattr(consent, "launch_consent", lambda plan_id: helper())
    lease = ServiceLease()
    monkeypatch.setattr(lease, "_call", lambda op, **args: {"plan_id": "a" * 32})
    result = lease.approve("trust_host", {"host": "example.test"})
    assert isinstance(result, ApprovalResult)
    assert not result and result.code == expected


def test_approval_service_failure_is_distinct(monkeypatch) -> None:
    lease = ServiceLease()
    monkeypatch.setattr(lease, "_call", lambda op, **args: None)
    assert lease.approve("trust_host", {}).code == "SERVICE_UNAVAILABLE"
    monkeypatch.setattr(lease, "_call", lambda op, **args: (_ for _ in ()).throw(
        ServiceError("REQUESTER_MISMATCH")))
    assert lease.approve("trust_host", {}).code == "REQUESTER_MISMATCH"


def test_helper_exit_codes_survive_pythonw(monkeypatch) -> None:
    monkeypatch.setattr(consent, "active_version", lambda: None)
    monkeypatch.setattr(sys, "argv", ["consent", "--plan-id", "a" * 32])
    monkeypatch.setattr(consent, "confirm", lambda plan_id: False)
    assert consent.main() == consent.HELPER_EXITS["DECLINED"]
    monkeypatch.setattr(consent, "confirm", lambda plan_id: (_ for _ in ()).throw(
        ServiceError("REQUESTER_MISMATCH")))
    assert consent.main() == consent.HELPER_EXITS["REQUESTER_MISMATCH"]
    monkeypatch.setattr(consent, "confirm", lambda plan_id: (_ for _ in ()).throw(
        ServiceUnavailable("SERVICE_UNAVAILABLE")))
    assert consent.main() == consent.HELPER_EXITS["SERVICE_UNAVAILABLE"]
    monkeypatch.setattr(consent, "confirm", lambda plan_id: (_ for _ in ()).throw(RuntimeError("broken")))
    assert consent.main() == consent.HELPER_EXITS["HELPER_FAILED"]


def test_the_helper_writes_nothing_into_the_state_tree() -> None:
    # Owned by whoever approved, such a file would fail the service's next start.
    source = (Path(consent.__file__)).read_text(encoding="utf-8")
    assert "RotatingFileHandler" not in source and ".state(" not in source and "logging" not in source


def test_tray_explains_owner_mismatch_and_silences_cancel(monkeypatch) -> None:
    from sentinel import tray

    assert "cùng một tài khoản" in tray._approval_message("REQUESTER_MISMATCH", "khôi phục")
    shown: list[str] = []
    monkeypatch.setattr(tray.messagebox, "showerror", lambda title, text: shown.append(text))
    tray._show_approval_failure(ApprovalResult(False, "CANCELLED"), "khôi phục")
    assert shown == []
    tray._show_approval_failure(ApprovalResult(False, "EXPIRED"), "khôi phục")
    assert "hết hạn" in shown[0]


def test_new_database_has_new_allow_store_id(tmp_path: Path) -> None:
    first = Database(tmp_path / "first.db")
    second = Database(tmp_path / "second.db")
    try:
        old_id = first.store_id()
        assert len(old_id) == 32
        assert first.store_id() == old_id
        assert second.store_id() != old_id
        first.close()
        reopened = Database(tmp_path / "first.db")
        try:
            assert reopened.store_id() == old_id
        finally:
            reopened.close()
    finally:
        second.close()


def test_native_host_service_version_includes_store_id(tmp_path: Path) -> None:
    class Lease:
        def status(self):
            return {"allow_store_id": "b" * 32, "allow_version": "0"}

        def allowed_hosts(self, offset, limit):
            return {"allow_store_id": "b" * 32, "allow_version": "0",
                    "hosts": [], "total": 0, "offset": offset}

    db = Database(tmp_path / "host.db")
    try:
        host = Host(db, object(), lease=Lease())
        assert host.on_hello({})["allow_version"] == "s" + "b" * 32 + ":0"
        assert host.on_get_allowlist({})["allow_version"] == "s" + "b" * 32 + ":0"
        local = Host(db, object())
        assert local.on_hello({})["allow_version"] == db.store_id() + ":0"
    finally:
        db.close()


def test_service_ipc_exposes_the_database_store_id(tmp_path: Path) -> None:
    db = Database(tmp_path / "service.db")
    try:
        backend = FakeBackend()
        backend.db = db
        backend.allowed_hosts = lambda offset, limit: {"allow_version": "0", "hosts": [],
                                                        "total": 0, "offset": offset}
        core = ServiceCore(backend)
        assert call(core, USER, "status")["result"]["allow_store_id"] == db.store_id()
        assert call(core, USER, "allowed_hosts", offset=0, limit=20)["result"]["allow_store_id"] == db.store_id()
    finally:
        db.close()


def test_native_host_keeps_approval_failure_code(tmp_path: Path) -> None:
    class Lease:
        def available(self):
            return True

        def approve(self, kind, params):
            return ApprovalResult(False, "REQUESTER_MISMATCH")

    db = Database(tmp_path / "native.db")
    try:
        with pytest.raises(BadRequest, match="approval:REQUESTER_MISMATCH"):
            Host(db, object(), lease=Lease()).on_allow_host({"host": "example.test"})
        assert db.allowed_hosts() == []
    finally:
        db.close()


def test_extension_notifies_once_when_first_service_list_clears_trust() -> None:
    source = (ROOT / "extension/src/background.js").read_text(encoding="utf-8")
    assert "serviceAllowSeen: false" in source
    assert "hello.allow_version !== state.allowVersion" in source
    assert "firstServiceList && state.allowHosts.length && !allowHosts.length" in source
    assert "serviceAllowSeen: state.serviceAllowSeen || serviceList" in source
    assert "Bạn có thể tin cậy lại một trang qua hộp xác nhận." in source
    assert "const APPROVAL_MS = 310000" in source
    assert "approvalNotice(code);" in source


def test_e2e_stops_before_launch_when_service_is_installed() -> None:
    source = (ROOT / "tools/helium_e2e.mjs").read_text(encoding="utf-8")
    assert source.index('spawnSync("sc.exe"') < source.index("mkdtempSync(")
    assert source.index("if (serviceInstalled && !withService)") < source.index("mkdtempSync(")
    assert 'process.argv.includes("--with-service")' in source
    assert 'not_meaningful: ["crafted_proceed_rejected", "once_not_trusted"]' in source
