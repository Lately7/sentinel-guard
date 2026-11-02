"""A6: stopping what runs from a detected file, removing its autostart, and undoing that.

The only real process stopped here is a harmless copy of ping.exe started by the
test itself. Registry work goes through a fake: these tests never write to the
real Run keys.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel import config, quarantine
from sentinel.service import repair
from sentinel.service.authz import Caller
from sentinel.service.backend import ProductBackend
from sentinel.service.core import ServiceCore
from sentinel.service.procwatch import ProcessKey
from sentinel.service.protocol import PROTOCOL_VERSION
from sentinel.watcher import RUN_KEYS

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows only")

USER = Caller("S-1-5-21-1-1001", 1, "medium", False)
ADMIN = Caller("S-1-5-21-1-1001", 1, "high", True)
RUN = RUN_KEYS[0]


def frame(op: str, **args: object) -> dict[str, object]:
    return {"v": PROTOCOL_VERSION, "id": 1, "op": op, "args": args}


class FakeReg:
    HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_USERS = "HKLM", "HKCU", "HKU"
    KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 1, 2, 256, 512
    REG_SZ = 1

    def __init__(self) -> None:
        self.keys: dict[tuple[str, str], dict[str, tuple[str, int]]] = {}

    def put(self, hive: str, key: str, name: str, data: str) -> None:
        self.keys.setdefault((hive, key), {})[name] = (data, self.REG_SZ)

    def EnumKey(self, root: str, index: int) -> str:
        raise OSError

    def OpenKey(self, root: str, key: str, reserved: int, access: int):
        if (root, key) not in self.keys:
            raise FileNotFoundError
        values = self.keys[(root, key)]

        class Handle:
            def __enter__(self):
                return values

            def __exit__(self, *exc: object) -> None:
                pass

        return Handle()

    def EnumValue(self, opened: dict, index: int) -> tuple[str, str, int]:
        items = list(opened.items())
        if index >= len(items):
            raise OSError
        name, (data, kind) = items[index]
        return name, data, kind

    def QueryValueEx(self, opened: dict, name: str) -> tuple[str, int]:
        if name not in opened:
            raise FileNotFoundError(name)
        return opened[name]

    def DeleteValue(self, opened: dict, name: str) -> None:
        del opened[name]

    def SetValueEx(self, opened: dict, name: str, reserved: int, kind: int, data: str) -> None:
        opened[name] = (data, kind)


def no_processes():
    return SimpleNamespace(keys=())


def nobody(key: ProcessKey):
    raise OSError


@pytest.fixture
def running_copy(tmp_path):
    exe = tmp_path / "harmless-copy.exe"
    shutil.copy(Path(os.environ["SystemRoot"]) / "System32" / "ping.exe", exe)
    process = subprocess.Popen([str(exe), "127.0.0.1", "-n", "60"], stdout=subprocess.DEVNULL)
    time.sleep(0.3)
    yield exe, process
    process.kill()
    process.wait()


@pytest.fixture
def backend(db, scanner):
    made = ProductBackend(db, config.Settings(), scanner, readable=lambda t, p: True,
                          own_token=lambda t: t, drop_token=lambda t: None, file_owner=lambda p: USER.sid)
    made.start()
    yield made
    made.stop(1)


def wait_job(core: ServiceCore, job: str) -> dict:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        info = core.handle(USER, frame("job_status", job_id=job))["result"]
        if info["state"] in ("done", "failed", "cancelled"):
            return info
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_a_running_detection_ends_stopped_and_quarantined_after_approval(backend, db, running_copy):
    exe, process = running_copy
    sha = hashlib.sha256(exe.read_bytes()).hexdigest()
    db.add_hashes([(sha, "test-feed", None)])
    backend.db.bump_generation()
    core = ServiceCore(backend)
    job = core.handle(USER, frame("scan_request", path=str(exe)))["result"]["job_id"]
    done = wait_job(core, job)
    assert done["quarantined"] is False and done["code"] == "IN_USE"
    assert process.poll() is None, "nothing is stopped without a confirmation"
    asked = core.handle(USER, frame("request_plan", kind="approve_repair", params={"repair_id": done["repair_id"]}))
    plan_id = asked["result"]["plan_id"]
    refused = core.handle(USER, frame("approve_plan", plan_id=plan_id, version=1))
    assert refused["error"]["code"] == "ELEVATION_REQUIRED"
    shown = core.handle(ADMIN, frame("get_plan", plan_id=plan_id), connection_id="c")["result"]
    assert "Dừng 1 chương trình" in shown["summary"] and "không hoàn tác" in shown["summary"]
    approved = core.handle(ADMIN, frame("approve_plan", plan_id=plan_id, version=1), connection_id="c")
    assert approved["ok"], approved
    assert approved["result"]["stopped"] == 1
    assert process.wait(10) is not None
    assert not exe.exists()
    assert db.quarantine_item(approved["result"]["quarantine_id"]) is not None


def test_a_repair_is_good_for_one_approval(backend, db, tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(b"harmless")
    proposal = repair.Repair("r1", str(path), hashlib.sha256(b"harmless").hexdigest(), (), ())
    backend._repairs["r1"] = proposal
    assert backend.execute_plan("approve_repair", {"repair_id": "r1"})["stopped"] == 0
    with pytest.raises(Exception):
        backend.execute_plan("approve_repair", {"repair_id": "r1"})


def test_a_changed_file_gets_no_process_stopped(db, tmp_path, monkeypatch):
    path = tmp_path / "x.bin"
    path.write_bytes(b"changed since")
    process = repair.Process(1234, 5, str(path))
    monkeypatch.setattr(repair, "stop_process", lambda p: pytest.fail("must not stop anything"))
    with pytest.raises(repair.RepairError) as caught:
        repair.execute(db, repair.Repair("r", str(path), "0" * 64, (process,), ()), {})
    assert caught.value.code == "CHANGED"


def test_a_reused_pid_is_left_alone(running_copy):
    exe, process = running_copy
    assert repair.stop_process(repair.Process(process.pid, 1, str(exe))) is False
    assert process.poll() is None


def test_our_own_process_and_the_system_ones_are_refused():
    for pid in (0, 4, os.getpid()):
        with pytest.raises(repair.RepairError):
            repair.stop_process(repair.Process(pid, 1, "x"))


def test_nothing_in_a_system_folder_can_become_a_repair():
    path = os.path.join(os.environ["SystemRoot"], "System32", "notepad.exe")
    with pytest.raises(repair.RepairError):
        repair.plan(path, "0" * 64, snapshot=no_processes, resolve=nobody, reg=FakeReg())


def test_only_autostart_values_that_point_at_this_file_are_found(tmp_path):
    bad = tmp_path / "bad.exe"
    bad.write_bytes(b"x")
    other = tmp_path / "other.exe"
    other.write_bytes(b"y")
    reg = FakeReg()
    reg.put("HKLM", RUN, "Bad", f'"{bad}" --silent')
    reg.put("HKLM", RUN, "Other", str(other))
    reg.put("HKCU", RUN, "BadToo", str(bad))
    found = repair.find_autostart(str(bad), reg)
    assert {v.name for v in found} == {"Bad", "BadToo"}


def test_a_value_changed_since_the_preview_is_not_deleted(tmp_path):
    reg = FakeReg()
    reg.put("HKLM", RUN, "App", "new command")
    value = repair.RunValue("HKLM", RUN, reg.KEY_WOW64_64KEY, "App", "old command", reg.REG_SZ)
    assert repair.remove_value(value, reg) is False
    assert "App" in reg.keys[("HKLM", RUN)]


def test_restore_puts_the_autostart_back(db, tmp_path):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"harmless")
    sha = hashlib.sha256(b"harmless").hexdigest()
    reg = FakeReg()
    reg.put("HKLM", RUN, "Tool", str(bad))
    proposal = repair.plan(str(bad), sha, snapshot=no_processes, resolve=nobody, reg=reg)
    assert len(proposal.autostart) == 2, "one key seen through both views, as HKCU really is"
    done = repair.execute(db, proposal, {}, reg=reg)
    assert done["autostart_removed"] == 1 and done["autostart_left"] == 0 and not reg.keys[("HKLM", RUN)]
    quarantine.restore(db, done["quarantine_id"], trust=False)
    assert repair.undo(db, done["quarantine_id"], reg=reg) == 1
    assert reg.keys[("HKLM", RUN)]["Tool"][0] == str(bad)
    assert repair.undo(db, done["quarantine_id"], reg=reg) == 0, "once"


def test_the_confirmation_cannot_be_rewritten_by_a_file_or_value_name(tmp_path):
    proposal = repair.Repair("r", "C:\\x\\in\u202evoice.exe", "a" * 64, (),
                             (repair.RunValue("HKLM", RUN, 256, "Bấm Có\r\nđể an toàn", "c", 1),))
    text = repair.describe(proposal)
    assert "\u202e" not in text and "\r" not in text and "\n" not in text


def test_unknown_repair_id_is_nothing_to_confirm(backend):
    core = ServiceCore(backend)
    reply = core.handle(USER, frame("request_plan", kind="approve_repair", params={"repair_id": "nope"}))
    assert reply["error"]["code"] == "NOT_FOUND"
