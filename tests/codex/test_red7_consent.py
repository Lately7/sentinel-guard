from __future__ import annotations

from types import SimpleNamespace

from sentinel import overview_ui
from sentinel.service.authz import Caller
from sentinel.service.core import ServiceCore
from sentinel.service.repair import Repair, RunValue, describe


def _call(core: ServiceCore, caller: Caller, op: str, **args: object) -> dict:
    return core.handle(caller, {"v": 1, "id": 1, "op": op, "args": args})


# A medium-integrity requester can hide repair actions after the prompt's silent 500-character cut.
def test_long_repair_plan_is_not_silently_cut(tmp_path, sentinel_home):
    assert sentinel_home.parent == tmp_path
    values = tuple(RunValue("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                            f"entry-{n}-" + "x" * 250, "target", 1) for n in range(4))
    proposal = Repair("repair-1", r"C:\Users\u\Downloads\sample.exe", "a" * 64, (), values)
    full = describe(proposal)
    assert len(full) > 500

    class Backend:
        def describe_plan(self, kind, params):
            return full

        def execute_plan(self, kind, params):
            return {"done": True}

    core = ServiceCore(Backend())
    user = Caller("S-1-5-21-1001", 1, "medium", False)
    helper = Caller(user.sid, 1, "high", True)
    requested = _call(core, user, "request_plan", kind="approve_repair", params={"repair_id": "repair-1"})
    if requested["ok"]:
        shown = _call(core, helper, "get_plan", plan_id=requested["result"]["plan_id"])
        assert shown["ok"]
        assert shown["result"]["summary"] == full


# A medium-integrity process can leave the service off while the overview says protection is on.
def test_overview_reports_service_protection_off(tmp_path, sentinel_home):
    assert sentinel_home.parent == tmp_path
    now = 1000.0
    app = SimpleNamespace(
        realtime=SimpleNamespace(running=True),
        db=SimpleNamespace(feed_status=lambda: [{"updated": now}], get_meta=lambda *_: str(now)),
        engine_status=SimpleNamespace(snapshot=SimpleNamespace(clamav_status="ready")),
    )
    state = overview_ui.protection_state(app, now=now,
                                         service_status={"realtime": False, "worker_failure": ""})
    assert state.level != "ok"


# A service failure leaves machine protection off while the tray starts local protection.
def test_tray_does_not_claim_enabled_after_service_rejects(tmp_path, sentinel_home):
    assert sentinel_home.parent == tmp_path
    from sentinel.tray import App

    started = []
    settings = SimpleNamespace(realtime=False, save=lambda: None)
    app = SimpleNamespace(realtime=None, lease=SimpleNamespace(available=lambda: True,
                                                               enable_protection=lambda: False),
                          settings=settings, start_realtime=lambda: started.append(True), icon=None)
    App.toggle_realtime(app)
    assert started == []
    assert settings.realtime is False
