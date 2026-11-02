"""M7 service: the real backend behind ServiceCore, and the clients that yield to it.

Same-user and unelevated: a private pipe, the real restricted worker, harmless
bytes. LocalSystem behaviour stays with the owner's acceptance script.
"""

from __future__ import annotations

import hashlib
import itertools
import os
import subprocess
import threading
import time
import uuid
from dataclasses import replace

import pytest

from conftest import MARKER
from sentinel import config, nativehost, protection, quarantine
from sentinel.engine import clamav
from sentinel.engine.scanner import Scanner
from sentinel.service import bridge, consent, entry, winpipe
from sentinel.service.authz import Caller
from sentinel.service.backend import ProductBackend, _host, shown
from sentinel.service.client import ServiceClient, ServiceError, WrongServer
from sentinel.service.core import MAX_JOBS_PER_CALLER, ServiceCore
from sentinel.service.protocol import PROTOCOL_VERSION
from sentinel.service.workerclient import Isolation

pytestmark = pytest.mark.skipif(os.name != "nt", reason="the service is Windows only")

USER = Caller("S-1-5-21-1-1001", 1, "medium", False)
ADMIN = Caller("S-1-5-21-1-1001", 1, "high", True)
OTHER = Caller("S-1-5-21-1-1002", 2, "medium", False)


def frame(op: str, **args: object) -> dict[str, object]:
    return {"v": PROTOCOL_VERSION, "id": 1, "op": op, "args": args}


def wait_job(core: ServiceCore, caller: Caller, job_id: str, seconds: float = 40.0) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        reply = core.handle(caller, frame("job_status", job_id=job_id))
        assert reply["ok"], reply
        if reply["result"]["state"] in ("done", "cancelled", "failed"):
            return reply["result"]
        time.sleep(0.02)
    raise AssertionError("job did not finish")


@pytest.fixture
def backend(db, scanner):
    readable: list[str] = []
    made = ProductBackend(db, config.Settings(), scanner, readable=lambda token, path: path not in readable,
                          own_token=lambda token: token, drop_token=lambda token: None)
    made.denied = readable
    made.start()
    yield made
    made.stop(1)


@pytest.fixture
def core(backend):
    return ServiceCore(backend)


def bad_file(tmp_path, name: str = "bad.bin"):
    path = tmp_path / name
    path.write_bytes(b"head " + MARKER + b" tail")
    return path


def submit(core: ServiceCore, caller: Caller, path) -> dict:
    reply = core.handle(caller, frame("scan_request", path=str(path)))
    assert reply["ok"], reply
    return wait_job(core, caller, reply["result"]["job_id"])


def plan(core: ServiceCore, kind: str, params: dict, *, caller: Caller = USER, approver: Caller = ADMIN) -> dict:
    asked = core.handle(caller, frame("request_plan", kind=kind, params=params))
    assert asked["ok"], asked
    shown_plan = core.handle(approver, frame("get_plan", plan_id=asked["result"]["plan_id"]), connection_id="c")
    assert shown_plan["ok"], shown_plan
    return core.handle(approver, frame("approve_plan", plan_id=asked["result"]["plan_id"], version=1), connection_id="c")


def test_client_cannot_decide_anything_only_name_a_file(core, db, tmp_path):
    bad = bad_file(tmp_path)
    done = submit(core, USER, bad)
    assert done["state"] == "done" and done["quarantined"] is True
    assert not bad.exists()
    assert done["verdict"]["label"] == "malicious"


def test_clean_file_is_left_alone(core, tmp_path):
    good = tmp_path / "good.txt"
    good.write_bytes(b"nothing here")
    done = submit(core, USER, good)
    assert done["quarantined"] is False and good.exists()


def test_file_swapped_after_the_access_check_is_not_acted_on(core, backend, tmp_path):
    # Passes the check on the name, then measures as a file this client cannot read.
    bad = bad_file(tmp_path)
    backend.denied.append(os.path.realpath(bad))
    real = backend._readable
    calls = []

    def first_yes(token, path):
        calls.append(path)
        return len(calls) == 1 or real(token, path)

    backend._readable = first_yes
    done = submit(core, replace(USER, token=1), bad)
    assert done == {"job_id": done["job_id"], "state": "done", "code": "ACCESS_DENIED"}
    assert bad.exists()


def test_quarantine_list_shows_a_user_only_their_own_items(core, tmp_path):
    mine = bad_file(tmp_path, "mine.bin")
    theirs = bad_file(tmp_path, "theirs.bin")
    submit(core, USER, mine)
    submit(core, OTHER, theirs)
    def names(caller: Caller) -> set[str]:
        return {os.path.basename(i["original_path"]) for i in core.handle(caller, frame("list_quarantine"))["result"]["items"]}
    assert names(USER) == {"mine.bin"}
    assert names(OTHER) == {"theirs.bin"}
    assert names(ADMIN) == {"mine.bin", "theirs.bin"}


def test_restore_needs_the_elevated_helper_and_excepts_only_that_file(core, db, scanner, tmp_path):
    bad = bad_file(tmp_path)
    qid = submit(core, USER, bad)["quarantine_id"]
    refused = core.handle(USER, frame("approve_plan", plan_id="0" * 32, version=1))
    assert refused["error"]["code"] == "ELEVATION_REQUIRED"
    done = plan(core, "restore_quarantine", {"quarantine_id": qid})
    assert done["ok"] and bad.exists()
    assert scanner.scan_file(bad).label == "clean"
    copy = tmp_path / "copy.bin"
    copy.write_bytes(bad.read_bytes())
    assert scanner.scan_file(copy).label == "malicious"


def test_restore_failure_reaches_the_client_as_a_code(core, tmp_path):
    bad = bad_file(tmp_path)
    qid = submit(core, USER, bad)["quarantine_id"]
    (config.quarantine_dir() / f"{qid}.qbin").write_bytes(b"damaged")
    done = plan(core, "restore_quarantine", {"quarantine_id": qid})
    assert done["error"]["code"] == "ACTION_FAILED"


def test_delete_needs_the_elevated_helper_too(core, db, tmp_path):
    qid = submit(core, USER, bad_file(tmp_path))["quarantine_id"]
    assert plan(core, "delete_quarantine", {"quarantine_id": qid})["ok"]
    assert db.quarantine_item(qid) is None


def test_trusting_a_host_goes_through_a_plan_and_is_normalised(core, db):
    assert plan(core, "trust_host", {"host": "Example.COM."})["ok"]
    assert db.is_host_allowed("example.com")
    assert core.handle(USER, frame("allowed_hosts"))["result"]["hosts"] == ["example.com"]


def test_look_alike_or_malformed_hosts_cannot_reach_the_confirmation(core):
    assert _host("xn--pple-43d.com") == "xn--pple-43d.com"
    assert _host("аpple.com") == "xn--pple-43d.com", "a Cyrillic look-alike is shown as what it really is"
    assert _host("exa mple.com") is None and _host("a/b") is None
    denied = core.handle(USER, frame("request_plan", kind="trust_host", params={"host": "bad host\nOK"}))
    assert denied["error"]["code"] == "NOT_FOUND"


def test_a_file_name_cannot_rewrite_the_confirmation_text():
    spoof = "invoice\u202egpj.exe\r\nNhấn Có để an toàn"
    cleaned = shown(spoof)
    assert "\u202e" not in cleaned and "\r" not in cleaned and "\n" not in cleaned


def test_trusting_content_needs_the_hash_of_the_file_now(core, db, tmp_path):
    path = tmp_path / "tool.bin"
    path.write_bytes(b"harmless")
    sha = hashlib.sha256(b"harmless").hexdigest()
    # Refused only at the elevated step: an unelevated caller learns nothing from the answer.
    assert plan(core, "add_exclusion", {"path": str(path), "sha256": "0" * 64})["error"]["code"] == "STALE_PLAN"
    assert not db.is_hash_allowed("0" * 64)
    assert plan(core, "add_exclusion", {"path": str(path), "sha256": sha})["ok"]
    assert db.is_hash_allowed(sha)


def test_changed_target_invalidates_a_displayed_plan(core, tmp_path):
    path = tmp_path / "tool.bin"
    path.write_bytes(b"harmless")
    sha = hashlib.sha256(b"harmless").hexdigest()
    asked = core.handle(USER, frame("request_plan", kind="add_exclusion", params={"path": str(path), "sha256": sha}))
    plan_id = asked["result"]["plan_id"]
    assert core.handle(ADMIN, frame("get_plan", plan_id=plan_id), connection_id="c")["ok"]
    path.write_bytes(b"something else")
    reply = core.handle(ADMIN, frame("approve_plan", plan_id=plan_id, version=1), connection_id="c")
    assert reply["error"]["code"] == "STALE_PLAN"


def test_off_stops_actions_survives_a_restart_and_only_an_admin_can_turn_it_off(core, backend, db, scanner, tmp_path):
    assert core.handle(USER, frame("status"))["result"]["realtime"] is True
    assert plan(core, "disable_protection", {})["ok"]
    assert core.handle(USER, frame("status"))["result"]["realtime"] is False
    bad = bad_file(tmp_path)
    done = submit(core, USER, bad)
    assert done["quarantined"] is False and bad.exists()
    assert done["verdict"]["label"] == "malicious", "off stops the action, not the verdict"
    later = ProductBackend(db, config.Settings(), scanner, readable=lambda t, p: True,
                           own_token=lambda t: t, drop_token=lambda t: None)
    later.start()
    assert later.status()["realtime"] is False
    later.stop(1)
    assert core.handle(USER, frame("enable_protection"))["ok"]
    assert submit(core, USER, bad)["quarantined"] is True


def test_stop_cancels_waiting_scans_and_refuses_new_ones(backend, core, tmp_path):
    assert backend.stop(1) is True
    reply = core.handle(USER, frame("scan_request", path=str(bad_file(tmp_path))))
    assert reply["error"]["code"] == "INTERNAL" or reply["error"]["code"] == "STOPPING"


def test_cancelled_job_does_not_act(core, backend, tmp_path, monkeypatch):
    bad = bad_file(tmp_path)
    started, go = threading.Event(), threading.Event()
    real = backend.scanner.scan_file

    def slow(path, **kwargs):
        started.set()
        go.wait(10)
        return real(path, **kwargs)

    monkeypatch.setattr(backend.scanner, "scan_file", slow)
    good = tmp_path / "good.txt"
    good.write_bytes(b"nothing")
    job = core.handle(USER, frame("scan_request", path=str(good)))["result"]["job_id"]
    started.wait(5)
    assert core.handle(USER, frame("cancel_job", job_id=job))["result"]["cancelled"] is True
    go.set()
    assert wait_job(core, USER, job)["state"] == "cancelled"
    assert bad.exists()


def test_a_caller_is_not_refused_for_good_after_many_finished_scans(backend, tmp_path):
    core = ServiceCore(backend, clock=itertools.count().__next__)  # a second per request: no rate limit here
    good = tmp_path / "good.txt"
    good.write_bytes(b"nothing")
    for _ in range(MAX_JOBS_PER_CALLER + 8):
        assert submit(core, USER, good)["state"] == "done"


def test_real_worker_scan_reaches_the_same_answer(db, marker_rule, tmp_path):
    iso = Isolation()
    scanner = Scanner(db, use_defender=False, isolation=iso)
    try:
        bad = bad_file(tmp_path)
        verdict = scanner.scan_file(bad, use_cache=False)
        assert verdict.label == "malicious"
        by_engine = {r.engine_id: r.status.value for r in verdict.decision.engine_results}
        assert by_engine["core"] == "completed" and by_engine["json_rules"] == "completed"
        assert iso.session is not None and iso.session.starts == 1
        assert {"core", "json_rules", "lnk", "signer"} <= set(iso.session.engines)
    finally:
        iso.close()


def test_a_fresh_install_with_no_rules_can_still_call_a_file_clean(db, tmp_path):
    # Seen only in a real runtime: every file came back unknown, for ever.
    iso = Isolation()
    try:
        good = tmp_path / "good.txt"
        good.write_bytes(b"nothing here")
        verdict = Scanner(db, use_defender=False, isolation=iso).scan_file(good, use_cache=False)
        assert verdict.label == "clean", verdict.decision.reason_codes
    finally:
        iso.close()


def test_real_worker_uses_the_service_hash_list(db, marker_rule, tmp_path):
    body = b"harmless bytes on a test list"
    path = tmp_path / "listed.bin"
    path.write_bytes(body)
    db.add_hashes([(hashlib.sha256(body).hexdigest(), "test-feed", None)])
    iso = Isolation()
    try:
        verdict = Scanner(db, use_defender=False, isolation=iso).scan_file(path, use_cache=False)
        assert verdict.label == "malicious"
    finally:
        iso.close()


def test_signed_file_is_checked_inside_the_worker_without_failing(db, marker_rule):
    iso = Isolation()
    try:
        path = os.path.join(os.environ["SystemRoot"], "explorer.exe")
        verdict = Scanner(db, use_defender=False, isolation=iso).scan_file(path, use_cache=False)
        signer = next(r for r in verdict.decision.engine_results if r.engine_id == "signer")
        assert signer.status.value != "error", signer.reason_code
    finally:
        iso.close()


# -- over the real pipe


@pytest.fixture
def running(db, marker_rule):
    me = winpipe.current_process_caller()
    name = rf"\\.\pipe\SentinelGuardTest\{uuid.uuid4().hex}"

    def make() -> ProductBackend:
        return ProductBackend(db, config.Settings(), Scanner(db, use_defender=False, isolation=Isolation()))

    service = entry.ProductService(make, name=name, sddl=f"D:P(A;;GA;;;{me.sid})")
    service.start()
    yield service, name, me.sid
    service.stop(5)


def test_whole_path_over_the_pipe_with_a_real_token(running, db, tmp_path):
    service, name, sid = running
    bad = bad_file(tmp_path)
    with ServiceClient(name, expected_sid=sid) as client:
        assert client.request("hello")["protocol"] == PROTOCOL_VERSION
        job = client.request("scan_request", path=str(bad))["job_id"]
        deadline = time.monotonic() + 40
        while (info := client.request("job_status", job_id=job))["state"] not in ("done", "failed"):
            assert time.monotonic() < deadline
            time.sleep(0.05)
        assert info["quarantined"] is True
        items = client.request("list_quarantine")["items"]
    assert [i["id"] for i in items] == [info["quarantine_id"]]
    assert not bad.exists()


def test_a_file_the_client_may_not_read_is_refused_over_the_pipe(running, tmp_path):
    service, name, sid = running
    secret = tmp_path / "secret.bin"
    secret.write_bytes(b"not for you")
    me = os.environ.get("USERNAME")
    subprocess.run(["icacls", str(secret), "/deny", f"{me}:(RD)"], check=True, stdout=subprocess.DEVNULL)
    try:
        with ServiceClient(name, expected_sid=sid) as client:
            with pytest.raises(ServiceError) as caught:
                client.request("scan_request", path=str(secret))
        assert caught.value.code == "ACCESS_DENIED"
    finally:
        subprocess.run(["icacls", str(secret), "/remove:d", me], check=True, stdout=subprocess.DEVNULL)


def test_stopping_closes_the_barrier_and_can_be_repeated(running):
    service, name, sid = running
    assert service.stop(1) is True
    assert service.stop(1) is True


# -- the clients


class Service:
    """Stands in for ServiceClient, answering through a real core."""

    def __init__(self, core: ServiceCore, caller: Caller = USER) -> None:
        self.core, self.caller = core, caller

    def __call__(self) -> "Service":
        return self

    def __enter__(self) -> "Service":
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    def request(self, op: str, **args: object) -> dict:
        reply = self.core.handle(self.caller, frame(op, **args))
        if not reply["ok"]:
            raise ServiceError(reply["error"]["code"])
        return reply["result"]


class Absent:
    def __enter__(self):
        raise bridge.ServiceUnavailable("SERVICE_UNAVAILABLE")

    def __exit__(self, *exc: object) -> None:
        pass


@pytest.fixture
def leased(core, monkeypatch):
    lease = bridge.ServiceLease(Service(core))
    monkeypatch.setattr(protection, "delegate", lease.confirm)
    return lease


def test_a_running_service_decides_and_the_local_process_only_records(leased, db, scanner, tmp_path):
    bad = bad_file(tmp_path)
    verdict = scanner.scan_file(bad)
    out = protection.act_on(db, verdict, config.Settings(), "scan")
    assert out["quarantined"] is True and not bad.exists()


def test_service_disagreeing_means_nothing_is_quarantined_here(leased, db, scanner, tmp_path, monkeypatch):
    good = tmp_path / "good.bin"
    good.write_bytes(b"head " + MARKER + b" tail")
    verdict = scanner.scan_file(good)
    good.write_bytes(b"now harmless")
    out = protection.act_on(db, verdict, config.Settings(), "scan")
    assert out["quarantined"] is False and good.exists()
    assert "xác nhận" in out["error"]


def test_a_hit_from_an_engine_the_service_lacks_is_not_lost(leased, db, scanner, tmp_path, monkeypatch):
    # The tray has ClamAV, the service does not: "found nothing" there proves nothing.
    bad = bad_file(tmp_path)
    verdict = scanner.scan_file(bad)
    monkeypatch.setattr(leased, "_scan", lambda op, **args: {
        "state": "done", "quarantined": False, "error": None, "trusted": False, "engines": ["core"]})
    out = protection.act_on(db, verdict, config.Settings(), "scan")
    assert out["quarantined"] is True and not bad.exists()


def test_an_administrators_trust_overrides_a_local_hit(leased, db, scanner, tmp_path, monkeypatch):
    bad = bad_file(tmp_path)
    verdict = scanner.scan_file(bad)
    monkeypatch.setattr(leased, "_scan", lambda op, **args: {
        "state": "done", "quarantined": False, "error": None, "trusted": True, "engines": []})
    out = protection.act_on(db, verdict, config.Settings(), "scan")
    assert out["quarantined"] is False and bad.exists()


def test_service_never_takes_clamd_from_a_folder_on_the_path(tmp_path, monkeypatch):
    planted = tmp_path / "clamd.exe"
    planted.write_bytes(b"not really")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("PATHEXT", ".EXE")
    monkeypatch.setenv("SENTINEL_CLAMAV_DIR", str(tmp_path))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "nowhere"))
    assert clamav.install_dir() == tmp_path, "user-level use keeps its overrides"
    monkeypatch.setattr(clamav, "machine_only", True)
    assert clamav.install_dir() is None


def test_no_service_means_the_tray_keeps_protecting_on_its_own(db, scanner, tmp_path, monkeypatch):
    lease = bridge.ServiceLease(Absent)
    monkeypatch.setattr(protection, "delegate", lease.confirm)
    bad = bad_file(tmp_path)
    out = protection.act_on(db, scanner.scan_file(bad), config.Settings(), "scan")
    assert out["quarantined"] is True and not bad.exists()
    assert quarantine.restore(db, out["quarantine_id"], trust=False).exists()


def test_a_squatted_pipe_is_treated_as_no_service(monkeypatch):
    class Squatted:
        def __enter__(self):
            raise WrongServer("WRONG_SERVER")

        def __exit__(self, *exc: object) -> None:
            pass

    assert bridge.ServiceLease(Squatted).available() is False


def test_unc_paths_stay_with_the_users_own_process(leased):
    class V:
        path = r"\\server\share\x.bin"

    assert leased.confirm(V()) is None


def test_native_host_cannot_write_the_allowlist_while_a_service_runs(leased, db, monkeypatch):
    host = nativehost.Host(db, config.Settings(), leased)
    monkeypatch.setattr(leased, "approve", lambda kind, params: False)
    reply = host.handle({"type": "allow_host", "host": "example.com", "id": 1})
    assert reply["ok"] is False
    assert not db.is_host_allowed("example.com")


def test_native_host_reads_allowances_and_url_verdicts_from_the_service(leased, core, db):
    assert plan(core, "trust_host", {"host": "example.com"})["ok"]
    host = nativehost.Host(db, config.Settings(), leased)
    page = host.handle({"type": "get_allowlist", "id": 1})
    assert page["hosts"] == ["example.com"] and page["allow_version"].startswith("s")
    assert host.handle({"type": "hello", "id": 2})["allow_version"] == page["allow_version"]
    assert host.handle({"type": "check_url", "url": "https://example.com/", "id": 3})["result"]["verdict"] == "allowed"


def test_native_host_download_scan_is_the_services_and_failure_is_not_a_result(leased, db, tmp_path, monkeypatch):
    host = nativehost.Host(db, config.Settings(), leased)
    bad = bad_file(tmp_path)
    reply = host.handle({"type": "scan_download", "path": str(bad), "id": 1})
    assert reply["ok"] and reply["quarantined"] is True and reply["verdict"]["label"] == "malicious"
    monkeypatch.setattr(leased, "scan_download", lambda path, url: {"state": "failed", "code": "X"})
    other = bad_file(tmp_path, "other.bin")
    assert host.handle({"type": "scan_download", "path": str(other), "id": 2})["ok"] is False


def test_consent_rejects_anything_but_a_plan_id():
    for bad in ("x" * 32, "0" * 31, "0" * 32 + "\n", "0" * 32 + " --evil"):
        with pytest.raises(consent.ConsentError):
            consent.validate_plan_id(bad)
