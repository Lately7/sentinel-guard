"""Restore replies and the download-mark warning."""

from __future__ import annotations

import sys
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel import __main__, quarantine, tray
from sentinel.service import backend, bridge, consent
from sentinel.service.bridge import ApprovalResult, RestoreApprovalResult, ServiceLease


WARNING = "không giữ được dấu tải từ Internet"
MISSING = object()


@pytest.mark.parametrize("preserved", [False, True, None, MISSING])
def test_consent_keeps_service_restore_reply(
    preserved: bool | None | object,
) -> None:
    reply = {} if preserved is MISSING else {"zone_identifier_preserved": preserved}

    class Client:
        def request(self, op: str, **args: object) -> dict[str, object]:
            if op == "get_plan":
                return {"plan_id": "a" * 32, "version": 1,
                        "kind": "restore_quarantine", "summary": "Khôi phục tệp"}
            assert op == "approve_plan"
            return reply

    result = consent.confirm("a" * 32, client=Client(), message_box=lambda *args: 6)

    assert isinstance(result, consent.RestoreConsent)
    assert result.zone_identifier_preserved is (None if preserved is MISSING else preserved)


@pytest.mark.parametrize("preserved", [False, True, None])
def test_restore_reply_survives_helper_exit_code(
    monkeypatch: pytest.MonkeyPatch, preserved: bool | None,
) -> None:
    monkeypatch.setattr(sys, "argv", ["consent", "--plan-id", "a" * 32])
    monkeypatch.setattr(consent, "confirm", lambda plan_id: consent.RestoreConsent(preserved))

    code = consent.main()
    decoded = consent._helper_result(code)

    assert code == consent.RESTORE_EXITS[preserved]
    assert isinstance(decoded, consent.RestoreConsent)
    assert decoded.zone_identifier_preserved is preserved


@pytest.mark.parametrize("preserved", [False, True, None])
def test_bridge_carries_restore_reply(
    monkeypatch: pytest.MonkeyPatch, preserved: bool | None,
) -> None:
    monkeypatch.setattr(consent, "launch_consent", lambda plan_id: consent.RestoreConsent(preserved))
    lease = ServiceLease()
    monkeypatch.setattr(lease, "_call", lambda op, **args: {"plan_id": "a" * 32})

    result = lease.approve("restore_quarantine", {"quarantine_id": "q1"})

    assert isinstance(result, RestoreApprovalResult) and result.approved
    assert result.zone_identifier_preserved is preserved


def test_other_approval_result_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consent, "launch_consent", lambda plan_id: True)
    lease = ServiceLease()
    monkeypatch.setattr(lease, "_call", lambda op, **args: {"plan_id": "a" * 32})

    result = lease.approve("delete_quarantine", {"quarantine_id": "q1"})

    assert type(result) is ApprovalResult
    assert result == ApprovalResult(True)


def test_older_helper_restore_result_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consent, "launch_consent", lambda plan_id: True)
    lease = ServiceLease()
    monkeypatch.setattr(lease, "_call", lambda op, **args: {"plan_id": "a" * 32})

    result = lease.approve("restore_quarantine", {"quarantine_id": "q1"})

    assert isinstance(result, RestoreApprovalResult)
    assert result.zone_identifier_preserved is None


@pytest.mark.parametrize("preserved", [False, True, None, MISSING])
def test_service_cli_warns_only_for_lost_download_mark(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    preserved: bool | None | object,
) -> None:
    from sentinel import db as db_module

    approval = RestoreApprovalResult(True) if preserved is MISSING else RestoreApprovalResult(
        True, zone_identifier_preserved=preserved)
    monkeypatch.setattr(db_module, "Database", lambda: object())
    monkeypatch.setattr(quarantine, "reconcile", lambda db: None)
    monkeypatch.setattr(bridge.lease, "quarantine_items", lambda: [{"id": "q1"}])
    monkeypatch.setattr(bridge.lease, "approve", lambda kind, params: approval)

    assert __main__.cmd_quarantine(Namespace(action="restore", id="q1")) == 0
    assert (WARNING in capsys.readouterr().out) is (preserved is False)


@pytest.mark.parametrize("preserved", [False, True, None, MISSING])
def test_service_tray_warns_only_for_lost_download_mark(
    monkeypatch: pytest.MonkeyPatch, preserved: bool | None | object,
) -> None:
    approval = RestoreApprovalResult(True) if preserved is MISSING else RestoreApprovalResult(
        True, zone_identifier_preserved=preserved)
    monkeypatch.setattr(tray.messagebox, "askyesno", lambda *args: True)
    warnings: list[str] = []
    monkeypatch.setattr(tray.messagebox, "showwarning", lambda title, text: warnings.append(text))
    app = object.__new__(tray.App)
    app.q_tv = SimpleNamespace(selection=lambda: ("q1",))
    app._service_items = {"q1"}
    app._service_repairs = {}
    app.lease = SimpleNamespace(approve=lambda kind, params: approval)
    app.refresh = lambda: None

    app.restore_selected()

    assert (len(warnings) == 1) is (preserved is False)
    if warnings:
        assert WARNING in warnings[0]


@pytest.mark.parametrize("preserved", [True, False, None])
def test_service_restore_reply_reports_download_mark(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, preserved: bool | None,
) -> None:
    path = quarantine.RestoredPath(tmp_path / "restored.bin", zone_identifier_preserved=preserved)
    monkeypatch.setattr(backend.quarantine, "restore", lambda db, qid: path)
    monkeypatch.setattr(backend.repair, "undo", lambda db, qid: False)
    events: list[tuple[object, ...]] = []
    product = object.__new__(backend.ProductBackend)
    product.db = SimpleNamespace(add_event=lambda *args: events.append(args))

    result = product.execute_plan("restore_quarantine", {"quarantine_id": "q1"})

    assert result == {"restored": str(path), "autostart_restored": False,
                      "zone_identifier_preserved": preserved}
    assert len(events) == 1


@pytest.mark.parametrize("preserved", [True, False, None])
def test_local_cli_warns_only_when_download_mark_was_lost(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    tmp_path: Path, preserved: bool | None,
) -> None:
    path = quarantine.RestoredPath(tmp_path / "restored.bin", zone_identifier_preserved=preserved)
    monkeypatch.setattr(quarantine, "reconcile", lambda db: None)
    monkeypatch.setattr(quarantine, "restore", lambda db, qid: path)
    from sentinel import db as db_module
    from sentinel.service import bridge

    monkeypatch.setattr(db_module, "Database", lambda: SimpleNamespace(quarantine_items=lambda: []))
    monkeypatch.setattr(bridge.lease, "quarantine_items", lambda: [])

    assert __main__.cmd_quarantine(Namespace(action="restore", id="q1")) == 0
    output = capsys.readouterr().out
    assert str(path) in output
    assert (WARNING in output) is (preserved is False)


@pytest.mark.parametrize("preserved", [True, False, None])
def test_local_tray_warns_only_when_download_mark_was_lost(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, preserved: bool | None,
) -> None:
    path = quarantine.RestoredPath(tmp_path / "restored.bin", zone_identifier_preserved=preserved)
    monkeypatch.setattr(tray.quarantine, "restore", lambda db, qid: path)
    monkeypatch.setattr(tray.messagebox, "askyesno", lambda *args: True)
    warnings: list[str] = []
    monkeypatch.setattr(tray.messagebox, "showwarning", lambda title, text: warnings.append(text))
    app = object.__new__(tray.App)
    app.q_tv = SimpleNamespace(selection=lambda: ("q1",))
    app._service_items = set()
    app._service_repairs = {}
    app.db = SimpleNamespace(add_event=lambda *args: None)
    app.refresh = lambda: None

    app.restore_selected()

    assert (len(warnings) == 1) is (preserved is False)
    if warnings:
        assert WARNING in warnings[0]
