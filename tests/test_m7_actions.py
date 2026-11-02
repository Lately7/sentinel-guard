"""M7 actions: quarantine and restore bound to the object that was scanned (R11 invariants 10, 11, 13)."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

from conftest import MARKER
from sentinel import config, quarantine
from sentinel.engine import scanner as scanner_module
from sentinel.gate_v2 import winfile
from sentinel.gate_v2.actions import ProtectionBarrier, ProtectionStopped
from sentinel.gate_v2.contract import ActionCode
from sentinel.gate_v2.identity import measure
from sentinel.protection import act_on

pytestmark = pytest.mark.skipif(os.name != "nt", reason="handle-based actions are Windows only")
BODY = b"harmless synthetic bytes"


def _sha(data: bytes = BODY) -> str:
    return hashlib.sha256(data).hexdigest()


def _junction(link: Path, target: Path) -> None:
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, stdout=subprocess.DEVNULL)


def test_quarantine_removes_every_hard_link(tmp_path, db):
    # R15-8: taking one name away would leave the same bytes one folder over.
    first = tmp_path / "first.bin"
    first.write_bytes(BODY)
    (tmp_path / "sub").mkdir()
    second = tmp_path / "sub" / "second.bin"
    os.link(first, second)
    qid = quarantine.quarantine(db, str(first), {"sha256": _sha()})
    assert not first.exists() and not second.exists()
    assert quarantine.restore(db, qid, trust=False).read_bytes() == BODY


def test_a_hard_link_in_a_protected_folder_stops_the_action(tmp_path, db, monkeypatch):
    # System files are hard links into WinSxS: the second name decides. Only for
    # a system-owned file: a user's own link there is no shield (test_m7_review).
    first = tmp_path / "first.bin"
    first.write_bytes(BODY)
    (tmp_path / "system").mkdir()
    second = tmp_path / "system" / "second.bin"
    os.link(first, second)
    root = os.path.normcase(str(tmp_path / "system"))
    monkeypatch.setattr(winfile, "protected_roots", lambda: (root,))
    monkeypatch.setattr(winfile.Target, "owner", lambda self: winfile.TRUSTED_INSTALLER)
    with pytest.raises(quarantine.QuarantineError) as caught:
        quarantine.quarantine(db, str(first), {"sha256": _sha()})
    assert caught.value.code == "PROTECTED_PATH"
    assert first.read_bytes() == BODY and second.read_bytes() == BODY
    assert not db.quarantine_items()


def test_system_folder_is_never_touched_but_its_temp_is_not_protected():
    windows = os.environ["SystemRoot"]
    assert winfile.is_protected(os.path.join(windows, "System32", "kernel32.dll"))
    assert not winfile.is_protected(os.path.join(windows, "Temp", "dropper.exe"))
    assert not winfile.is_protected(os.path.join(windows + "Old", "x.exe"))


def test_parent_swapped_for_a_junction_cannot_redirect_the_delete(tmp_path, db):
    # The classic way to turn an antivirus into an arbitrary-delete primitive.
    scanned = tmp_path / "folder"
    scanned.mkdir()
    path = scanned / "x.bin"
    path.write_bytes(BODY)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "x.bin").write_bytes(BODY)
    scanned.rename(tmp_path / "moved")
    _junction(scanned, victim)
    with pytest.raises(quarantine.QuarantineError) as caught:
        quarantine.quarantine(db, str(path), {"sha256": _sha()})
    assert caught.value.code == "CHANGED"
    assert (victim / "x.bin").read_bytes() == BODY
    assert not db.quarantine_items()


def test_junction_at_the_name_itself_is_not_followed(tmp_path, db):
    target = tmp_path / "target.bin"
    target.write_bytes(BODY)
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(target)
    except OSError as e:
        pytest.skip(f"symlinks unavailable: {e}")
    with pytest.raises(quarantine.QuarantineError) as caught:
        quarantine.quarantine(db, str(link), {"sha256": _sha()})
    assert caught.value.code == "REPARSE_POINT"
    assert target.exists() and link.is_symlink()


def test_links_are_refused_and_cloud_placeholders_are_not(tmp_path, db, monkeypatch):
    # Creating a real file symlink needs a privilege these tests do not have.
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    monkeypatch.setattr(winfile, "_reparse_tag", lambda *args: 0xA000000C)  # IO_REPARSE_TAG_SYMLINK
    with pytest.raises(quarantine.QuarantineError) as caught:
        quarantine.quarantine(db, str(path), {"sha256": _sha()})
    assert caught.value.code == "REPARSE_POINT"
    monkeypatch.setattr(winfile, "_reparse_tag", lambda *args: 0x9000001A)  # IO_REPARSE_TAG_CLOUD
    quarantine.quarantine(db, str(path), {"sha256": _sha()})
    assert not path.exists()


def test_restore_through_a_junction_writes_nothing_there(tmp_path, db):
    # The other half of the same trick: a privileged write into a folder of the
    # attacker's choosing, with content the attacker chose.
    parent = tmp_path / "folder"
    parent.mkdir()
    path = parent / "x.bin"
    path.write_bytes(BODY)
    qid = quarantine.quarantine(db, str(path), {"sha256": _sha()})
    parent.rmdir()
    target = tmp_path / "elsewhere"
    target.mkdir()
    _junction(parent, target)
    with pytest.raises(quarantine.QuarantineError) as caught:
        quarantine.restore(db, qid, trust=False)
    assert caught.value.code == "MOVED"
    assert list(target.iterdir()) == []
    assert db.quarantine_item(qid) is not None


def test_read_only_attribute_does_not_keep_a_file_out_of_quarantine(tmp_path, db):
    path = tmp_path / "ro.bin"
    path.write_bytes(BODY)
    path.chmod(0o444)
    quarantine.quarantine(db, str(path), {"sha256": _sha()})
    assert not path.exists()


def test_a_running_program_rolls_back_completely(tmp_path, db):
    exe = tmp_path / "harmless-copy.exe"
    shutil.copy(Path(os.environ["SystemRoot"]) / "System32" / "ping.exe", exe)
    process = subprocess.Popen([str(exe), "127.0.0.1", "-n", "30"], stdout=subprocess.DEVNULL)
    try:
        time.sleep(0.3)
        with pytest.raises(quarantine.QuarantineError) as caught:
            quarantine.quarantine(db, str(exe), {})
    finally:
        process.kill()
        process.wait()
    assert caught.value.code == "IN_USE"
    assert exe.exists()
    assert not db.quarantine_items() and not db.open_actions(time.time() + 1)
    assert not list(config.quarantine_dir().glob("*.qbin"))


def test_open_writer_blocks_the_claim_without_touching_anything(tmp_path, db):
    path = tmp_path / "busy.bin"
    path.write_bytes(BODY)
    with path.open("ab"):
        with pytest.raises(quarantine.QuarantineError) as caught:
            quarantine.quarantine(db, str(path), {"sha256": _sha()})
    assert caught.value.code == "IN_USE"
    assert path.read_bytes() == BODY


def test_same_name_new_file_is_not_quarantined_for_the_old_one(tmp_path, db):
    # Identical bytes at the same name are still another file generation.
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    measured = measure(str(path)).identity
    assert measured is not None
    path.unlink()
    path.write_bytes(BODY)
    with pytest.raises(quarantine.QuarantineError) as caught:
        quarantine.quarantine(db, str(path), {}, expected=measured)
    assert caught.value.code == "CHANGED"


def test_restored_download_keeps_its_mark_of_the_web(tmp_path, db):
    path = tmp_path / "setup.bin"
    path.write_bytes(BODY)
    mark = "[ZoneTransfer]\r\nZoneId=3\r\n"
    with open(str(path) + ":Zone.Identifier", "w", encoding="utf-8", newline="") as stream:
        stream.write(mark)
    qid = quarantine.quarantine(db, str(path), {"sha256": _sha()})
    restored = quarantine.restore(db, qid, trust=False)
    with open(str(restored) + ":Zone.Identifier", encoding="utf-8", newline="") as stream:
        assert stream.read() == mark


def test_crash_before_the_delete_leaves_one_copy_at_home(tmp_path, db, monkeypatch):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)

    class Crash(BaseException):
        pass

    def die(self, delete=True):
        raise Crash

    monkeypatch.setattr(winfile.Target, "mark_delete", die)
    with pytest.raises(Crash):
        quarantine.quarantine(db, str(path), {"sha256": _sha()})
    monkeypatch.undo()
    assert len(db.quarantine_items()) == 1, "the crash stopped after recording"
    assert quarantine.reconcile(db, grace=60) == 0, "a recent row may belong to another live process"
    assert quarantine.reconcile(db, grace=-1) == 1
    assert path.read_bytes() == BODY
    assert not db.quarantine_items() and not list(config.quarantine_dir().glob("*.qbin"))


def test_crash_after_the_delete_keeps_the_only_copy(tmp_path, db):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY)
    qid = quarantine.quarantine(db, str(path), {"sha256": _sha()})
    db.open_action(qid, str(path), _sha())
    assert quarantine.reconcile(db, grace=-1) == 1
    assert db.quarantine_item(qid) is not None
    assert not db.open_actions(time.time() + 1)
    assert quarantine.restore(db, qid, trust=False).read_bytes() == BODY


def test_two_threads_quarantine_one_file_once(tmp_path, db):
    path = tmp_path / "x.bin"
    path.write_bytes(BODY * 1000)
    done: list[str] = []

    def one() -> None:
        try:
            done.append(quarantine.quarantine(db, str(path), {}))
        except quarantine.QuarantineError:
            pass

    threads = [threading.Thread(target=one) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(done) == 1 and len(db.quarantine_items()) == 1


def test_barrier_refuses_after_revoke_and_waits_for_running_actions():
    barrier = ProtectionBarrier()
    generation = barrier.current()
    with barrier.action(generation):
        assert barrier.revoke(0.05) is False, "still running"
        assert barrier.current() is None
    assert barrier.revoke(0.05) is True
    with pytest.raises(ProtectionStopped):
        with barrier.action():
            pass
    barrier.resume()
    with pytest.raises(ProtectionStopped):
        with barrier.action(generation):  # a scan from before the stop stays stopped
            pass
    with barrier.action(barrier.current()):
        pass


def test_protection_stopped_during_the_scan_cancels_the_action(db, scanner, tmp_path, monkeypatch):
    barrier = ProtectionBarrier()
    path = tmp_path / "bad.bin"
    path.write_bytes(b"head " + MARKER + b" tail")
    assert scanner.scan_file(path, barrier=barrier, use_cache=False).decision.action_decision.action is ActionCode.QUARANTINE

    def stop_midway(*args, **kwargs):
        barrier.revoke(0)

    monkeypatch.setattr(scanner_module.cache, "lookup", stop_midway)
    action = scanner.scan_file(path, barrier=barrier, use_cache=False).decision.action_decision
    assert (action.action, action.reason_code) == (ActionCode.NONE, "PROTECTION_STOPPED")


def test_scan_started_while_protection_is_off_cannot_act(db, scanner, tmp_path):
    barrier = ProtectionBarrier()
    barrier.revoke(0)
    path = tmp_path / "bad.bin"
    path.write_bytes(b"head " + MARKER + b" tail")
    action = scanner.scan_file(path, barrier=barrier, use_cache=False).decision.action_decision
    assert (action.action, action.reason_code) == (ActionCode.NONE, "PROTECTION_STOPPED")


def test_scan_job_shows_the_check_that_is_running(db, scanner, tmp_path):
    from sentinel import scanjob

    path = tmp_path / "x.txt"
    path.write_bytes(b"hello")
    seen: list[str] = []
    job = scanjob.ScanJob(scanner, db, config.Settings(), [str(path)], "t")
    real = job._on_stage

    def spy(*args, **kwargs):
        real(*args, **kwargs)
        seen.append(job.progress.stage)

    job._on_stage = spy
    job.start().join(30)
    assert "core" in seen, "the stage comes from the gate's own events"


def test_changed_file_is_reported_in_vietnamese_and_stays(db, scanner, tmp_path):
    path = tmp_path / "bad.bin"
    path.write_bytes(b"head " + MARKER + b" tail")
    verdict = scanner.scan_file(path)
    with path.open("ab") as stream:
        stream.write(b"more")
    out = act_on(db, verdict, config.Settings(), "scan")
    assert out["quarantined"] is False
    assert "đổi" in out["error"]
    assert path.exists()
