"""Regression tests for the independent review of the action and service code.

Each test names the finding it holds in place. All of them use harmless bytes;
nothing here touches a real Run key or a real system file.
"""

from __future__ import annotations

import ctypes
import hashlib
import io
import itertools
import json
import os
import subprocess
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import MARKER
from sentinel import config, quarantine, urlintel
from sentinel import protection
from sentinel.gate_v2 import identity, scope, winfile
from sentinel.gate_v2.contract import ActionCode, StageStatus
from sentinel.service import backend as backend_module
from sentinel.service import bridge, repair, usn, winpipe
from sentinel.service.authz import Caller
from sentinel.service.backend import ProductBackend, _Job, _Lane
from sentinel.service.core import ServiceCore, local_path
from sentinel.service.observers import DbCursorStore, Observers
from sentinel.service.protocol import PROTOCOL_VERSION, read_frame, write_frame
from sentinel.service.usn import JournalCursor
from sentinel.service.winpipe import SERVICE_SDDL
from sentinel.watcher import ScanQueue

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows only")

USER = Caller("S-1-5-21-1-1001", 1, "medium", False)
ADMIN = Caller("S-1-5-21-1-1001", 1, "high", True)
OTHER = Caller("S-1-5-21-1-1002", 2, "medium", False)
BODY = b"harmless synthetic bytes"


def frame(op: str, **args: object) -> dict[str, object]:
    return {"v": PROTOCOL_VERSION, "id": 1, "op": op, "args": args}


def wait_job(core: ServiceCore, caller: Caller, job: str, seconds: float = 40.0) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        info = core.handle(caller, frame("job_status", job_id=job))["result"]
        if info["state"] in ("done", "failed", "cancelled"):
            return info
        time.sleep(0.02)
    raise AssertionError("job did not finish")


@pytest.fixture
def backend(db, scanner):
    denied: list[str] = []
    made = ProductBackend(db, config.Settings(), scanner, readable=lambda token, path: path not in denied,
                          own_token=lambda token: token, drop_token=lambda token: None,
                          file_owner=lambda path: USER.sid)
    made.denied = denied
    made.start()
    yield made
    made.stop(1)


@pytest.fixture
def core(backend):
    return ServiceCore(backend, clock=itertools.count().__next__)


def bad_file(tmp_path: Path, name: str = "bad.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(b"head " + MARKER + b" tail")
    return path


def plan(core: ServiceCore, kind: str, params: dict) -> dict:
    asked = core.handle(USER, frame("request_plan", kind=kind, params=params))
    assert asked["ok"], asked
    plan_id = asked["result"]["plan_id"]
    assert core.handle(ADMIN, frame("get_plan", plan_id=plan_id), connection_id="c")["ok"]
    return core.handle(ADMIN, frame("approve_plan", plan_id=plan_id, version=1), connection_id="c")


def submit(core: ServiceCore, caller: Caller, op: str = "scan_request", **args: object) -> dict:
    reply = core.handle(caller, frame(op, **args))
    assert reply["ok"], reply
    return wait_job(core, caller, reply["result"]["job_id"])


# 1 -- a client's word


def test_a_listed_url_from_a_client_never_makes_the_service_delete_a_clean_file(core, tmp_path, monkeypatch):
    clean = tmp_path / "program.dll"
    clean.write_bytes(BODY)
    monkeypatch.setattr(urlintel, "check", lambda db, url: {
        "verdict": "malicious", "matched": "bad.example", "kind": "malware", "source": "test", "url": url})
    done = submit(core, USER, "download_hint", path=str(clean), url="http://bad.example/x")
    assert done["quarantined"] is False and clean.read_bytes() == BODY
    assert done["verdict"]["label"] == "clean"
    assert done["url_reputation"]["verdict"] == "malicious", "still reported to the browser"


# 2 -- paths


@pytest.mark.parametrize("path", [
    "\\/srv/share/x", "\\/./pipe/x", "//srv/share/x", "\\\\srv\\share\\x", "\\\\.\\pipe\\x", "\\\\?\\C:\\x",
    "\\??\\C:\\x", "C:relative", "relative\\x", "C:\\", "C:\\a\\..\\b.exe", "C:\\a\\.\\b.exe", "C:\\a.txt:stream",
    "C:\\dir\\NUL", "C:\\dir\\com1.txt", "C:\\a.exe.", "C:\\a.exe ", "C:\\a\\\\b.exe", "C:\\a\x01b.exe",
])
def test_only_one_plain_spelling_of_a_local_path_reaches_the_service(path):
    assert local_path(path) is None


def test_forward_slashes_are_normalised_not_refused():
    assert local_path("C:/Users/u/Downloads/setup.exe") == "C:\\Users\\u\\Downloads\\setup.exe"


def test_the_exclusion_plan_is_no_oracle_for_a_file_the_caller_cannot_read(core, backend, tmp_path):
    secret = tmp_path / "secret.bin"
    secret.write_bytes(BODY)
    backend.denied.append(str(secret))
    sha = hashlib.sha256(BODY).hexdigest()
    reply = core.handle(USER, frame("request_plan", kind="add_exclusion", params={"path": str(secret), "sha256": sha}))
    assert reply["error"]["code"] == "ACCESS_DENIED"


# 3 -- the production pipe


def test_a_client_asks_only_for_what_the_service_grants_interactive_users():
    granted = int(SERVICE_SDDL.rsplit("(A;;", 1)[1].split(";", 1)[0], 16)
    assert winpipe.CLIENT_ACCESS & ~granted == 0
    assert granted & 0x4 == 0, "a user must never be able to add a pipe instance"


def test_a_client_really_connects_through_the_production_acl():
    me = winpipe.current_process_caller()
    name = rf"\\.\pipe\SentinelGuardTest\{uuid.uuid4().hex}"
    server = winpipe.PipeServer(ServiceCore(SimpleNamespace()), name=name, sddl=f"D:P(A;;0x0012008B;;;{me.sid})")
    try:
        winpipe.connect(name).close()
    finally:
        winpipe._k32.CloseHandle(server._pending)


# 4 -- restore


def test_restore_makes_no_folder_through_a_junction(db, tmp_path):
    base = tmp_path / "base"
    (base / "a" / "b").mkdir(parents=True)
    path = base / "a" / "b" / "x.bin"
    path.write_bytes(BODY)
    qid = quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(BODY).hexdigest()})
    (base / "a" / "b").rmdir()
    (base / "a").rmdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(base / "a"), str(victim)], check=True, stdout=subprocess.DEVNULL)
    with pytest.raises(quarantine.QuarantineError):
        quarantine.restore(db, qid, trust=False)
    assert list(victim.iterdir()) == []


def test_the_mark_of_the_web_is_written_to_the_held_file_not_to_a_name(db, tmp_path, monkeypatch):
    path = tmp_path / "setup.bin"
    path.write_bytes(BODY)
    mark = "[ZoneTransfer]\r\nZoneId=3\r\n"
    with open(str(path) + ":Zone.Identifier", "w", encoding="utf-8", newline="") as stream:
        stream.write(mark)
    qid = quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(BODY).hexdigest()})
    real_open = open
    monkeypatch.setattr("builtins.open", lambda name, *a, **k: pytest.fail(f"opened by name: {name}")
                        if str(name).endswith(":Zone.Identifier") else real_open(name, *a, **k))
    restored = quarantine.restore(db, qid, trust=False)
    monkeypatch.undo()
    with open(str(restored) + ":Zone.Identifier", encoding="utf-8", newline="") as stream:
        assert stream.read() == mark


# 5 -- oplocks


def test_a_file_that_blocks_on_open_holds_up_nothing_else(db, tmp_path, monkeypatch):
    stuck = tmp_path / "stuck.bin"
    stuck.write_bytes(BODY)
    other = tmp_path / "other.bin"
    other.write_bytes(BODY)
    entered, release = threading.Event(), threading.Event()
    real = quarantine._zone_identifier

    def blocking(path: str):
        if path == str(stuck):
            entered.set()
            release.wait(10)
        return real(path)

    monkeypatch.setattr(quarantine, "_zone_identifier", blocking)
    thread = threading.Thread(target=lambda: quarantine.quarantine(db, str(stuck), {}))
    thread.start()
    entered.wait(5)
    finished = threading.Event()
    threading.Thread(target=lambda: (quarantine.quarantine(db, str(other), {}), finished.set()), daemon=True).start()
    try:
        assert finished.wait(5), "an unrelated quarantine must not wait for the stuck one"
    finally:
        release.set()
        thread.join(10)


def test_watching_the_journal_never_waits_on_a_file(db, scanner):
    entered = threading.Event()
    release = threading.Event()

    def blocking(path: str):
        entered.set()
        release.wait(10)
        return None

    made = ProductBackend(db, config.Settings(), scanner, file_owner=blocking)
    try:
        started = time.monotonic()
        assert made.observe("C:\\x\\y.exe", "journal") is True
        assert time.monotonic() - started < 1
    finally:
        release.set()
        made.stop(1)


def test_a_stuck_scan_is_written_off_and_the_lane_goes_on():
    release = threading.Event()
    done: list[str] = []

    def run(job: _Job) -> None:
        if job.path == "stuck":
            release.wait(10)
        done.append(job.path)

    now = [0.0]
    lane = _Lane("test", 1, run, limit=100.0, clock=lambda: now[0])
    try:
        stuck = _Job("1", "stuck", "journal", None, "", None)
        lane.submit(stuck)
        time.sleep(0.1)
        lane.submit(_Job("2", "next", "journal", None, "", None))
        time.sleep(0.2)
        assert done == []
        now[0] = 200.0
        lane.sweep()
        deadline = time.monotonic() + 5
        while "next" not in done and time.monotonic() < deadline:
            time.sleep(0.01)
        assert done == ["next"] and stuck.state == "failed" and stuck.result["code"] == "STALLED" and lane.stalled == 1
    finally:
        release.set()
        lane.stop()


# 6 -- names NTFS allows and UTF-8 does not


def lone_surrogate(tmp_path: Path) -> Path:
    path = tmp_path / "bad\ud800name.bin"
    path.write_bytes(b"head " + MARKER + b" tail")
    return path


def test_a_lone_surrogate_in_a_name_is_scanned_quarantined_and_restored(db, scanner, tmp_path):
    bad = lone_surrogate(tmp_path)
    verdict = scanner.scan_file(bad)
    assert verdict.label == "malicious"
    out = protection.act_on(db, verdict, config.Settings(), "scan")
    assert out["quarantined"] is True and not bad.exists()
    assert db.events(5), "an event, not a silent failure"
    assert list(config.quarantine_dir().glob("*.qbin"))
    assert quarantine.restore(db, out["quarantine_id"], trust=False) == bad
    assert bad.exists()


def test_a_lone_surrogate_crosses_the_pipe():
    buffer = io.BytesIO()
    write_frame(buffer, {"path": "bad\ud800.bin"})
    buffer.seek(0)
    assert read_frame(buffer) == {"path": "bad\ud800.bin"}


def test_native_messages_survive_a_lone_surrogate():
    from sentinel import nativehost

    buffer = io.BytesIO()
    nativehost.write_message(buffer, {"id": 1, "verdict": {"path": "bad\ud800.bin"}})
    assert b"response too large" not in buffer.getvalue()


def test_one_odd_name_does_not_throw_away_a_batch_of_journal_records():
    raw = "ab\ud800.exe".encode("utf-16-le", "surrogatepass")
    length = (60 + len(raw) + 7) & ~7
    head = (length.to_bytes(4, "little") + (2).to_bytes(2, "little") + bytes(2) + (7).to_bytes(8, "little")
            + (5).to_bytes(8, "little") + (100).to_bytes(8, "little") + bytes(8)
            + (usn.USN_REASON_CLOSE | usn.USN_REASON_FILE_CREATE).to_bytes(4, "little") + bytes(12)
            + len(raw).to_bytes(2, "little") + (60).to_bytes(2, "little"))
    record = usn.parse_record(head + raw + bytes(length - 60 - len(raw)))
    assert record is not None and record.name == "ab\ud800.exe"


# 7 -- the delete mark


def test_a_handle_that_clears_the_mark_cannot_make_quarantine_lie(db, tmp_path, monkeypatch):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    earlier = winfile.open_target(str(path))
    real_close = winfile.Target.close
    cleared: list[bool] = []

    def close(self):
        if self is not earlier and not cleared:
            cleared.append(True)
            earlier.mark_delete(False)
            # Windows honours the last word, whoever said it: clear ours too.
            self.mark_delete(False)
        real_close(self)

    monkeypatch.setattr(winfile.Target, "close", close)
    try:
        with pytest.raises(quarantine.QuarantineError) as caught:
            quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(BODY).hexdigest()})
    finally:
        monkeypatch.undo()
        earlier.close()
    assert caught.value.code == "IN_USE"
    assert path.read_bytes() == BODY
    assert not db.quarantine_items() and not list(config.quarantine_dir().glob("*.qbin"))


def test_a_handle_held_elsewhere_does_not_stop_the_file_going(db, tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    earlier = winfile.open_target(str(path))
    try:
        quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(BODY).hexdigest()})
        assert not os.path.lexists(path), "gone from its folder at once, whoever still holds it"
        assert earlier.gone()
    finally:
        earlier.close()


# 8 -- findings that reached nobody


def test_what_the_service_found_by_itself_reaches_its_owner_only(core, backend, db, tmp_path):
    db.add_event("realtime", "threat", "Phát hiện", "a.exe", {"owner_sid": USER.sid, "repair_id": "r1"})
    db.add_event("realtime", "threat", "Phát hiện", "b.exe", {"owner_sid": OTHER.sid})
    mine = core.handle(USER, frame("events", after=0))["result"]
    assert [e["detail"] for e in mine["events"]] == ["a.exe"] and mine["events"][0]["repair_id"] == "r1"
    assert core.handle(USER, frame("events", after=mine["last"]))["result"]["events"] == []
    assert len(core.handle(ADMIN, frame("events", after=0))["result"]["events"]) == 2


def test_a_running_threat_found_with_nobody_watching_offers_its_repair(backend, db, tmp_path, monkeypatch):
    bad = bad_file(tmp_path, "bad.exe")
    held = winfile._open(str(bad), winfile.GENERIC_READ, winfile.FILE_SHARE_READ, winfile.OPEN_EXISTING, 0,
                         os.O_RDONLY | os.O_BINARY, "rb")
    monkeypatch.setattr(repair, "plan", lambda path, sha, **k: repair.Repair("r9", path, sha, (), ()))
    try:
        backend.observe(str(bad), "journal")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not any(
                json.loads(e["data"] or "{}").get("repair_id") == "r9" for e in db.events(20)):
            time.sleep(0.02)
    finally:
        held.close()
    assert any(json.loads(e["data"] or "{}").get("repair_id") == "r9" for e in db.events(20))


# 9 -- files that would not hold still


def test_touching_a_file_does_not_dodge_quarantine(db, scanner, tmp_path):
    bad = bad_file(tmp_path)
    verdict = scanner.scan_file(bad)
    os.utime(bad, (1000, 2000))
    out = protection.act_on(db, verdict, config.Settings(), "scan")
    assert out["quarantined"] is True and not bad.exists()


def test_a_touch_during_the_gate_does_not_cancel_the_action(tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    measured = identity.measure(str(path)).identity
    os.utime(path, (1000, 2000))
    assert identity.revalidate(str(path), measured, rehash=True).ok
    path.write_bytes(BODY + b"!")
    assert not identity.revalidate(str(path), measured, rehash=True).ok


def test_changed_bytes_still_stop_the_action(db, scanner, tmp_path):
    bad = bad_file(tmp_path)
    verdict = scanner.scan_file(bad)
    with bad.open("ab") as stream:
        stream.write(b"more")
    out = protection.act_on(db, verdict, config.Settings(), "scan")
    assert out["quarantined"] is False and out["code"] == "CHANGED"


def test_a_file_held_exclusively_is_an_answer_not_a_crash_and_is_tried_again(backend, db, tmp_path, monkeypatch):
    path = tmp_path / "held.exe"
    path.write_bytes(BODY)
    held = winfile._open(str(path), winfile.GENERIC_READ, 0, winfile.OPEN_EXISTING, 0, os.O_RDONLY | os.O_BINARY, "rb")
    core = ServiceCore(backend, clock=itertools.count().__next__)
    try:
        done = submit(core, USER, path=str(path))
        assert done["state"] == "done" and done["verdict"]["label"] == "unknown"
        job = _Job("1", str(path), "journal", None, "", None)
        backend._observed.acquire()
        backend._run_observed(job)
    finally:
        held.close()
    assert backend._later and backend._later[0][1] == str(path), "tried again later, not forgotten"


def test_giving_up_on_a_file_is_reported(backend, db, tmp_path):
    path = tmp_path / "held.exe"
    path.write_bytes(BODY)
    job = _Job("1", str(path), "journal", None, USER.sid, None, attempts=len(backend_module.RETRY_SECONDS))
    job.state, job.result = "failed", {"code": "SCAN_FAILED"}
    backend._after_observed(job)
    assert not backend._later
    assert any("Chưa kiểm tra" in e["title"] for e in db.events(5))


def test_watcher_requeues_on_the_typed_code(db, scanner, tmp_path, monkeypatch):
    queue = ScanQueue(scanner, db, config.Settings())
    path = bad_file(tmp_path)
    again: list[str] = []
    monkeypatch.setattr(queue, "_requeue", lambda p, delay, attempts=0: again.append(p))
    monkeypatch.setattr(queue, "_act", lambda v: {"error": "tệp đã đổi", "code": "CHANGED", "quarantined": False})
    queue._scan_one(str(path), 0)
    assert again == [str(path)]


# 10 -- protected folders


@pytest.mark.parametrize("tail", ["Tasks\\x.exe", "Tracing\\x.exe", "System32\\Tasks\\x.exe",
                                  "System32\\spool\\drivers\\color\\x.exe", "Temp\\x.exe"])
def test_folders_any_user_can_write_to_are_not_protected(tail):
    assert not winfile.is_protected(os.path.join(os.environ["SystemRoot"], tail))


def test_a_users_own_hard_link_in_a_system_folder_is_no_shield(db, tmp_path, monkeypatch):
    first = tmp_path / "first.bin"
    first.write_bytes(BODY)
    (tmp_path / "writable").mkdir()
    second = tmp_path / "writable" / "second.bin"
    os.link(first, second)
    root = os.path.normcase(str(tmp_path / "writable"))
    monkeypatch.setattr(winfile, "protected_roots", lambda: (root,))
    quarantine.quarantine(db, str(first), {"sha256": hashlib.sha256(BODY).hexdigest()})
    assert not first.exists() and not second.exists()


def test_a_system_owned_file_in_a_protected_folder_stays_untouched(db, tmp_path, monkeypatch):
    path = tmp_path / "sys.bin"
    path.write_bytes(BODY)
    monkeypatch.setattr(winfile, "protected_roots", lambda: (os.path.normcase(str(tmp_path)),))
    monkeypatch.setattr(winfile.Target, "owner", lambda self: winfile.TRUSTED_INSTALLER)
    with pytest.raises(quarantine.QuarantineError) as caught:
        quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(BODY).hexdigest()})
    assert caught.value.code == "PROTECTED_PATH" and path.exists()


def test_an_unknown_owner_counts_as_the_system(tmp_path, monkeypatch):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    target = winfile.open_target(str(path))
    try:
        assert target.owner() == winpipe.current_process_caller().sid
        monkeypatch.setattr(winfile.Target, "owner", lambda self: None)
        assert target.system_owned()
    finally:
        target.close()


# 11 -- silent drops


class Fake:
    root = "C:\\"

    def __init__(self) -> None:
        self.query = (9).to_bytes(8, "little") + bytes(8) + (1000).to_bytes(8, "little") + bytes(8) + (1 << 62).to_bytes(8, "little") + bytes(16)

    def control(self, code: int, data: bytes, size: int) -> bytes:
        if code == usn.FSCTL_QUERY_USN_JOURNAL:
            return self.query
        return (1000).to_bytes(8, "little")

    def resolve(self, record: usn.UsnRecord) -> str | None:
        return None


def watcher(db, submit, **options) -> Observers:
    store = DbCursorStore(db)
    store.save(JournalCursor("C:\\", 9, 1000, 0.0))
    return Observers(submit, [Fake()], store, **options)


def test_a_rewrite_right_after_an_offer_is_offered_again(db):
    offered: list[str] = []
    now = [0.0]
    seen = watcher(db, lambda path, reason, fresh=False: offered.append(path) or True, clock=lambda: now[0])
    seen._offer("C:\\a.exe", "journal")
    now[0] = 2.0
    seen._offer("C:\\a.exe", "journal")
    seen.tick_journal()
    assert offered == ["C:\\a.exe"], "still inside the window"
    now[0] = 11.0
    seen.tick_journal()
    assert offered == ["C:\\a.exe", "C:\\a.exe"]


def test_a_full_queue_is_made_up_for(db):
    calls: list[int] = []
    seen = watcher(db, lambda path, reason, fresh=False: False, reconcile=lambda: calls.append(1) or True,
                   clock=lambda: 0.0)
    seen._offer("C:\\a.exe", "journal")
    seen.tick_journal()
    assert calls == [1]


def test_trouble_during_the_quiet_hour_is_reconciled_afterwards(db):
    calls: list[int] = []
    now = [0.0]
    seen = watcher(db, lambda path, reason, fresh=False: True, reconcile=lambda: calls.append(1) or True,
                   clock=lambda: now[0])
    seen._owed = True
    seen.tick_journal()
    seen._owed = True
    now[0] = 10.0
    seen.tick_journal()
    assert calls == [1]
    now[0] = 4000.0
    seen.tick_journal()
    assert calls == [1, 1]


def test_a_reconciliation_the_queue_refused_is_still_owed(db):
    calls: list[int] = []
    now = [0.0]
    seen = watcher(db, lambda path, reason, fresh=False: True, reconcile=lambda: calls.append(1) or False,
                   clock=lambda: now[0])
    seen._owed = True
    seen.tick_journal()
    now[0] = 4000.0
    seen.tick_journal()
    assert calls == [1, 1]


# 12 -- what the confirmation shows


def test_spaces_and_length_cannot_hide_the_end_of_a_path():
    path = "C:\\Tools\\notepad.exe" + " " * 320 + "\\evil.dll"
    text = repair.shown_path(path)
    assert "evil.dll" in text and "notepad.exe" in text and len(text) < 300


def test_the_exclusion_prompt_names_the_file_that_was_measured(core, backend, tmp_path):
    path = tmp_path / "tool.bin"
    path.write_bytes(BODY)
    junction = tmp_path / "alias"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(tmp_path)], check=True, stdout=subprocess.DEVNULL)
    summary = backend.describe_plan("add_exclusion", {"path": str(junction / "tool.bin"),
                                                      "sha256": hashlib.sha256(BODY).hexdigest()})
    assert "alias" not in summary and "tool.bin" in summary


# 13 -- a service that did not look


def test_only_engines_that_finished_count_as_having_looked(backend):
    results = (SimpleNamespace(engine_id="core", status=StageStatus.ERROR),
               SimpleNamespace(engine_id="yara_x", status=StageStatus.COMPLETED))
    decision = SimpleNamespace(identity=None, engine_results=results, reason_codes=())
    verdict = SimpleNamespace(label="clean", path=None, decision=decision, findings=[], to_dict=lambda **k: {})
    job = _Job("1", "x", "on_demand", None, USER.sid, None)
    assert backend._finish(job, verdict, None)["engines"] == ["yara_x"]


@pytest.mark.parametrize("answer", [
    {"state": "failed", "code": "SCAN_FAILED"},
    {"state": "done", "code": "ACCESS_DENIED"},
    {"state": "done", "quarantined": False, "error": None, "trusted": False, "engines": []},
])
def test_a_service_that_could_not_look_leaves_the_decision_here(db, scanner, tmp_path, monkeypatch, answer):
    lease = bridge.ServiceLease(lambda: None)
    monkeypatch.setattr(lease, "available", lambda: True)
    monkeypatch.setattr(lease, "_scan", lambda op, **args: answer)
    verdict = scanner.scan_file(bad_file(tmp_path))
    assert lease.confirm(verdict) is None


def test_a_refused_scan_also_leaves_the_decision_here(core, backend, tmp_path):
    bad = bad_file(tmp_path)
    backend.denied.append(str(bad))

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

        def request(self, op, **args):
            reply = core.handle(USER, frame(op, **args))
            if not reply["ok"]:
                raise bridge.ServiceError(reply["error"]["code"])
            return reply["result"]

    lease = bridge.ServiceLease(Client)
    assert lease.confirm(SimpleNamespace(path=str(bad), decision=None)) is None


# 14 -- long confirmations


def test_a_long_confirmation_can_still_be_approved(core, backend, tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    sha = hashlib.sha256(BODY).hexdigest()
    values = tuple(repair.RunValue("HKLM", "k", 256, "n" * 90 + str(i), "d", 1) for i in range(4))
    backend._repairs["r1"] = repair.Repair("r1", str(path), sha, (), values)
    assert len(repair.describe(backend._repairs["r1"])) > 300
    backend.describe_plan = lambda kind, params: "x" * 900
    backend.execute_plan = lambda kind, params: {"done": True}
    assert plan(core, "approve_repair", {"repair_id": "r1"})["ok"]


# 15 -- the rest


def test_the_quarantined_copy_reaches_the_disk_before_the_original_goes(db, tmp_path, monkeypatch):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    order: list[str] = []
    real_fsync, real_mark = os.fsync, winfile.Target.mark_delete
    monkeypatch.setattr(os, "fsync", lambda fd: (order.append("fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(winfile.Target, "mark_delete", lambda self, delete=True: (order.append("delete"), real_mark(self, delete))[1])
    quarantine.quarantine(db, str(path), {})
    assert order[:2] == ["fsync", "delete"]


def test_run_values_of_another_user_expand_in_that_users_profile():
    command = '"%APPDATA%\\tool\\a.exe" --x %LocalAppData%\\b.exe'
    expanded = scope.for_profile(command, "C:\\Users\\other")
    assert expanded == '"C:\\Users\\other\\AppData\\Roaming\\tool\\a.exe" --x C:\\Users\\other\\AppData\\Local\\b.exe'


def test_protection_stopped_still_records_without_acting(db, scanner, tmp_path):
    from sentinel.gate_v2.actions import ProtectionBarrier

    barrier = ProtectionBarrier()
    barrier.revoke(0)
    bad = bad_file(tmp_path)
    assert scanner.scan_file(bad, barrier=barrier).decision.action_decision.action is ActionCode.NONE


def test_a_second_claim_on_a_file_already_taken_records_nothing(db, tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    second = quarantine._open_names(str(path), None)
    quarantine.quarantine(db, str(path), {})
    with pytest.raises(quarantine.QuarantineError) as caught:
        quarantine._quarantine(db, path, second, {}, None, None)
    assert caught.value.code == "MISSING"
    assert len(db.quarantine_items()) == 1


def test_a_long_path_shows_both_ends():
    path = "C:\\" + "folder\\" * 60 + "evil.dll"
    text = repair.shown_path(path)
    assert text.startswith("C:\\folder") and text.endswith("evil.dll") and len(text) < 170


def test_a_failed_service_leaves_even_a_finding_with_no_evidence_here(tmp_path, monkeypatch):
    lease = bridge.ServiceLease(lambda: None)
    monkeypatch.setattr(lease, "available", lambda: True)
    monkeypatch.setattr(lease, "_scan", lambda op, **args: {"state": "failed", "code": "SCAN_FAILED"})
    assert lease.confirm(SimpleNamespace(path=str(tmp_path / "x"), decision=None)) is None


def test_what_the_service_finds_alone_belongs_to_the_files_owner(core, backend, tmp_path):
    bad = bad_file(tmp_path, "bad.exe")
    assert backend.observe(str(bad), "journal") is True
    deadline = time.monotonic() + 15
    while bad.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    time.sleep(0.2)
    items = core.handle(USER, frame("list_quarantine"))["result"]["items"]
    assert [os.path.basename(i["original_path"]) for i in items] == ["bad.exe"]
    assert core.handle(OTHER, frame("list_quarantine"))["result"]["items"] == []


def test_a_verdict_with_no_decision_is_still_an_answer(backend):
    verdict = SimpleNamespace(label="clean", path=None, decision=None, findings=[], to_dict=lambda **k: {})
    job = _Job("1", "x", "on_demand", None, USER.sid, None)
    assert backend._finish(job, verdict, None)["engines"] == []


# Second round: what the same reviewer found in the fixes


def test_a_lane_gets_its_threads_back_after_many_stalls():
    release = threading.Event()
    done: list[str] = []

    def run(job: _Job) -> None:
        if job.path.startswith("stuck"):
            release.wait(10)
        done.append(job.path)

    now = [0.0]
    lane = _Lane("test", 1, run, limit=1.0, clock=lambda: now[0])
    try:
        for i in range(backend_module.MAX_STUCK + 4):
            lane.submit(_Job(str(i), f"stuck{i}", "journal", None, "", None))
            deadline = time.monotonic() + 5
            while not lane.running and time.monotonic() < deadline:
                time.sleep(0.005)
            now[0] += 5.0
            lane.sweep()
            time.sleep(0.01)
        assert lane.stalled >= backend_module.MAX_STUCK
        release.set()
        lane.submit(_Job("z", "clean", "journal", None, "", None))
        deadline = time.monotonic() + 5
        while "clean" not in done and time.monotonic() < deadline:
            time.sleep(0.01)
        assert "clean" in done, "stuck threads gave their places back"
        deadline = time.monotonic() + 5
        while lane.stuck and time.monotonic() < deadline:
            time.sleep(0.01)
        assert lane.stuck == 0
    finally:
        release.set()
        lane.stop()


def test_a_written_off_file_reaches_somebody(backend, db):
    job = _Job("1", "C:\\x\\y.exe", "journal", None, USER.sid, None)
    backend._observed_lane.on_stall(job)
    assert any("Chưa kiểm tra" in e["title"] for e in db.events(5))


def test_a_hard_link_made_during_the_copy_goes_too(db, tmp_path, monkeypatch):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    late = tmp_path / "late.bin"
    real = quarantine._copy_xor

    def copy(src, dest):
        os.link(path, late)
        return real(src, dest)

    monkeypatch.setattr(quarantine, "_copy_xor", copy)
    quarantine.quarantine(db, str(path), {})
    assert not path.exists() and not late.exists()


def test_a_link_too_late_to_catch_is_a_failure_not_a_claim(db, tmp_path, monkeypatch):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    late = tmp_path / "late.bin"
    real = winfile.Target.mark_delete

    def mark(self, delete=True):
        if delete and not late.exists():
            os.link(path, late)
        real(self, delete)

    monkeypatch.setattr(winfile.Target, "mark_delete", mark)
    with pytest.raises(quarantine.QuarantineError) as caught:
        quarantine.quarantine(db, str(path), {})
    assert caught.value.code == "IN_USE"
    assert late.read_bytes() == BODY
    assert not db.quarantine_items() and not list(config.quarantine_dir().glob("*.qbin"))


def test_cleaning_up_a_redirected_folder_removes_only_what_was_created(tmp_path, monkeypatch):
    item = tmp_path / "new"
    decoy = str(item)
    real = winfile.identity._final_path

    def flipped(descriptor, path):
        os.rename(str(item), str(tmp_path / "ours"))
        os.mkdir(decoy)  # by now the name leads to something that was already there
        return "C:\\elsewhere"

    monkeypatch.setattr(winfile.identity, "_final_path", flipped)
    with pytest.raises(winfile.TargetError):
        winfile.make_parents(str(item / "x.bin"))
    monkeypatch.setattr(winfile.identity, "_final_path", real)
    assert item.is_dir(), "what the name led to afterwards is not ours to remove"
    assert not (tmp_path / "ours").exists()


def test_a_page_of_events_fits_a_frame_and_later_events_still_arrive(core, db):
    for i in range(195):
        db.add_event("realtime", "warning", "t", "\U0001f600" * 900 + str(i), {"owner_sid": USER.sid})
    db.add_event("realtime", "threat", "last", "the one that matters", {"owner_sid": USER.sid})
    seen: list[str] = []
    after = 0
    for _ in range(20):
        reply = core.handle(USER, frame("events", after=after))
        assert reply["ok"], reply
        buffer = io.BytesIO()
        write_frame(buffer, reply)
        seen += [e["title"] for e in reply["result"]["events"]]
        if reply["result"]["last"] == after:
            break
        after = reply["result"]["last"]
    assert "last" in seen


def test_a_pipe_behind_a_path_is_not_a_file():
    me = winpipe.current_process_caller()
    name = rf"\\.\pipe\SentinelGuardTest\{uuid.uuid4().hex}"
    server = winpipe.PipeServer(ServiceCore(SimpleNamespace()), name=name, sddl=f"D:P(A;;GA;;;{me.sid})")
    try:
        assert winpipe.open_for_query(name) is None
        assert winpipe.file_owner(name) is None
    finally:
        winpipe._k32.CloseHandle(server._pending)


def test_a_wrong_hash_tells_an_unelevated_caller_nothing(core, tmp_path):
    path = tmp_path / "tool.bin"
    path.write_bytes(BODY)
    wrong = core.handle(USER, frame("request_plan", kind="add_exclusion", params={"path": str(path), "sha256": "0" * 64}))
    right = core.handle(USER, frame("request_plan", kind="add_exclusion",
                                    params={"path": str(path), "sha256": hashlib.sha256(BODY).hexdigest()}))
    assert wrong["ok"] and right["ok"] and set(wrong["result"]) == set(right["result"])


def test_files_owned_by_the_system_reach_every_tray(core, db):
    db.add_event("realtime", "threat", "t", "admin-owned.exe", {"owner_sid": "S-1-5-32-544"})
    db.add_event("system", "warning", "t", "private", {"admin_only": True})
    seen = [e["detail"] for e in core.handle(USER, frame("events", after=0))["result"]["events"]]
    assert seen == ["admin-owned.exe"]


def test_a_touch_loop_cannot_keep_a_detected_file_unknown(db, scanner, tmp_path):
    bad = bad_file(tmp_path)
    stop = threading.Event()

    def touch() -> None:
        tick = 1000
        while not stop.is_set():
            tick += 1
            os.utime(bad, (tick, tick))

    thread = threading.Thread(target=touch, daemon=True)
    thread.start()
    try:
        labels = {scanner.scan_file(bad, use_cache=False).label for _ in range(5)}
    finally:
        stop.set()
        thread.join(5)
    assert labels == {"malicious"}


def test_a_reconciliation_that_raises_is_still_owed(db):
    def broken():
        raise OSError("no")

    now = [0.0]
    seen = watcher(db, lambda path, reason, fresh=False: True, reconcile=broken, clock=lambda: now[0])
    seen._owed = True
    with pytest.raises(OSError):
        seen.tick_journal()
    assert seen._owed is True


def test_a_rescan_the_queue_refused_is_asked_again(backend, monkeypatch):
    from sentinel.service.rescan import Download

    offered: list[bool] = []
    monkeypatch.setattr(backend, "observe", lambda path, reason, fresh=False: offered.append(True) and False)
    backend.rescans.remember(Download(1, 2, "C:\\d\\x.exe", "a" * 64, "g1", time.time()))
    backend._rule_generation = "g1"
    monkeypatch.setattr(backend.scanner, "gate_id", lambda: "g2")
    backend.rescan_on_new_rules()
    assert backend._rule_generation == "g1", "not done, so not marked done"


def test_a_retry_the_queue_refused_comes_round_again(backend, monkeypatch):
    monkeypatch.setattr(backend, "observe", lambda path, reason, fresh=False, attempts=0: False)
    backend._later.append((0.0, "C:\\x.exe", "journal", 2))
    backend._retry_due()
    assert [item[1:] for item in backend._later] == [("C:\\x.exe", "journal", 2)]


def test_the_record_is_on_disk_before_the_original_goes(db, tmp_path, monkeypatch):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    order: list[str] = []
    real_flush, real_mark = db.flush, winfile.Target.mark_delete
    monkeypatch.setattr(db, "flush", lambda: (order.append("flush"), real_flush())[1])
    monkeypatch.setattr(winfile.Target, "mark_delete", lambda self, delete=True: (order.append("delete"), real_mark(self, delete))[1])
    quarantine.quarantine(db, str(path), {})
    assert order[:2] == ["flush", "delete"]


# Third round


def test_a_file_swapped_while_quarantine_runs_neither_vanishes_nor_lies(db, tmp_path, monkeypatch):
    # The real file is the one held. A decoy put at the name must change nothing.
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    moved = tmp_path / "moved.bin"
    real = quarantine._quarantine

    def swapped_first(*args, **kwargs):
        # Between opening the file and starting on it, the moment a claim can wait.
        os.rename(path, moved)
        path.write_bytes(b"decoy")
        return real(*args, **kwargs)

    monkeypatch.setattr(quarantine, "_quarantine", swapped_first)
    qid = quarantine.quarantine(db, str(path), {})
    assert not moved.exists(), "the held file went"
    assert path.read_bytes() == b"decoy", "what was put at the name is not ours"
    assert db.quarantine_item(qid) is not None
    assert (config.quarantine_dir() / f"{qid}.qbin").is_file()


def test_a_delete_that_waits_holds_up_nothing_else(db, tmp_path, monkeypatch):
    stuck = tmp_path / "stuck.bin"
    stuck.write_bytes(BODY)
    other = tmp_path / "other.bin"
    other.write_bytes(BODY)
    entered, release = threading.Event(), threading.Event()
    real = winfile.Target.mark_delete

    def waits(self, delete=True):
        if delete and self.path.endswith("stuck.bin"):
            entered.set()
            release.wait(10)
        real(self, delete)

    monkeypatch.setattr(winfile.Target, "mark_delete", waits)
    thread = threading.Thread(target=lambda: quarantine.quarantine(db, str(stuck), {}))
    thread.start()
    entered.wait(5)
    finished = threading.Event()
    threading.Thread(target=lambda: (quarantine.quarantine(db, str(other), {}), finished.set()), daemon=True).start()
    try:
        assert finished.wait(5)
    finally:
        release.set()
        thread.join(10)


def test_a_touch_loop_ends_in_quarantine(db, scanner, tmp_path):
    bad = bad_file(tmp_path)
    stop = threading.Event()

    def touch() -> None:
        tick = 1000
        while not stop.is_set():
            tick += 1
            try:
                os.utime(bad, (tick, tick))
            except OSError:
                return

    thread = threading.Thread(target=touch, daemon=True)
    thread.start()
    try:
        verdict = scanner.scan_file(bad, use_cache=False)
        assert verdict.decision.action_decision.action is ActionCode.QUARANTINE
        out = protection.act_on(db, verdict, config.Settings(), "scan")
    finally:
        stop.set()
        thread.join(5)
    assert out["quarantined"] is True


def test_a_slow_observed_scan_is_replaced_not_cancelled():
    release = threading.Event()
    seen: list[bool] = []

    def run(job: _Job) -> None:
        if job.path == "slow":
            release.wait(10)
            seen.append(job.cancel.cancelled())
        else:
            seen.append(False)

    now = [0.0]
    lane = _Lane("test", 1, run, limit=60.0, give_up=150.0, clock=lambda: now[0])
    try:
        slow = _Job("1", "slow", "journal", None, "", None)
        lane.submit(slow)
        deadline = time.monotonic() + 5
        while not lane.running and time.monotonic() < deadline:
            time.sleep(0.005)
        now[0] = 61.0
        lane.sweep()
        lane.submit(_Job("2", "next", "journal", None, "", None))
        deadline = time.monotonic() + 5
        while not seen and time.monotonic() < deadline:
            time.sleep(0.005)
        assert seen == [False] and slow.state != "failed", "the next job ran beside it"
        release.set()
        deadline = time.monotonic() + 5
        while len(seen) < 2 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert seen == [False, False], "and the slow one finished uncancelled"
    finally:
        release.set()
        lane.stop()


def test_entra_users_keep_their_paths_private():
    caller = Caller("S-1-12-1-1-2-3-4", 1, "medium", False)
    assert backend_module._visible(caller, "S-1-12-1-1-2-3-4")
    assert not backend_module._visible(caller, "S-1-12-1-9-9-9-9")
    assert backend_module._visible(caller, "S-1-5-32-544")


def test_a_file_already_being_quarantined_is_refused_not_copied_twice(db, tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    probe = winfile.open_target(str(path))
    key = probe.key
    probe.close()
    quarantine._claims.add(key)
    try:
        with pytest.raises(quarantine.QuarantineError) as caught:
            quarantine.quarantine(db, str(path), {})
    finally:
        quarantine._claims.discard(key)
    assert caught.value.code == "ALREADY" and path.exists() and not db.quarantine_items()


def test_a_new_folder_is_held_from_its_creation_with_no_second_lookup(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "mkdir", lambda *a, **k: pytest.fail("a name-based create leaves a window"))
    monkeypatch.setattr(winfile._k32, "CreateFileW", lambda *a: pytest.fail("a second lookup of the name"))
    winfile.make_parents(str(tmp_path / "a" / "b" / "x.bin"))
    monkeypatch.undo()
    assert (tmp_path / "a" / "b").is_dir()


def test_nothing_observed_is_given_up_on_before_a_scan_could_have_finished(backend):
    lane = backend._observed_lane
    assert lane.limit < config.SCAN_DEADLINE_SECONDS < lane.give_up


def test_ctypes_structures_match_windows():
    assert ctypes.sizeof(winfile.FILE_STANDARD_INFO) == 24
