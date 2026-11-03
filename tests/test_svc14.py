"""Reconciliation offers remain bounded and resumable after journal loss."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from sentinel.gate_v2.scope import SourceEntry
from sentinel.service import reconcile


class Cursor:
    def __init__(self) -> None:
        self.value: str | None = None

    def get(self) -> str | None:
        return self.value

    def set(self, value: str) -> None:
        self.value = value


def _file(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"harmless")
    return str(path)


def _new(root: Path, cursor: Cursor, submit: Callable[[str, str], bool],
         **bounds: object) -> reconcile.Reconciler:
    data = root / "service-data"
    data.mkdir(exist_ok=True)
    return reconcile.Reconciler(submit, cursor.get, cursor.set, data_root=str(data),
                                smart_sources={}, drives=[str(root / "drive")], **bounds)


def test_smart_is_first_then_deep_offers_only_risky_files_outside_service_data(tmp_path: Path) -> None:
    boot = _file(tmp_path / "boot.exe")
    deep = _file(tmp_path / "drive" / "sub" / "changed.dll")
    _file(tmp_path / "drive" / "notes.txt")
    _file(tmp_path / "drive" / "service-data" / "private.exe")
    data = tmp_path / "drive" / "service-data"
    cursor = Cursor()
    seen: list[str] = []
    smart = {"run": lambda: iter((SourceEntry("run", "boot", boot),))}
    walker = reconcile.Reconciler(lambda path, reason: seen.append(path) or True,
                                  cursor.get, cursor.set, data_root=str(data),
                                  smart_sources=smart, drives=[str(tmp_path / "drive")])

    assert walker()
    assert seen == [boot, deep]
    assert walker.report()["complete"]


def test_offer_cap_and_persisted_cursor_resume_without_reoffering(tmp_path: Path) -> None:
    paths = {_file(tmp_path / "drive" / f"{n}.exe") for n in range(4)}
    cursor = Cursor()
    seen: list[str] = []
    submit = lambda path, reason: seen.append(path) or True
    first = _new(tmp_path, cursor, submit, max_offers=1, save_every=1)

    assert first() is False
    assert len(seen) == 1
    stored = json.loads(cursor.value or "")
    assert stored["phase"] == "deep" and len(stored["stack"]) == 1

    resumed = _new(tmp_path, cursor, submit, max_offers=1, save_every=1)
    for _ in range(5):
        if resumed():
            break
    assert resumed.report()["complete"]
    assert set(seen) == paths and len(seen) == len(paths)
    assert len(cursor.value or "") < 4096


def test_refused_offer_remains_at_cursor_until_accepted(tmp_path: Path) -> None:
    _file(tmp_path / "drive" / "a.exe")
    _file(tmp_path / "drive" / "b.exe")
    cursor = Cursor()
    calls: list[str] = []

    def submit(path: str, reason: str) -> bool:
        calls.append(path)
        return len(calls) > 1

    walker = _new(tmp_path, cursor, submit)
    assert walker() is False
    assert walker.report()["offered"] == 0
    assert walker()
    assert calls[0] == calls[1]
    assert walker.report()["offered"] == 2
    assert walker.report()["refused"] == 1


def test_submit_error_does_not_advance_the_deep_cursor(tmp_path: Path) -> None:
    only = _file(tmp_path / "drive" / "only.exe")
    cursor = Cursor()
    calls: list[str] = []

    def submit(path: str, reason: str) -> bool:
        calls.append(path)
        if len(calls) == 1:
            raise OSError("queue unavailable")
        return True

    walker = _new(tmp_path, cursor, submit)
    with pytest.raises(OSError):
        walker()
    assert walker()
    assert calls == [only, only]


def test_smart_offer_cap_does_not_skip_the_next_target(tmp_path: Path) -> None:
    first = _file(tmp_path / "first.exe")
    second = _file(tmp_path / "second.exe")
    data = tmp_path / "service-data"
    data.mkdir()
    cursor = Cursor()
    seen: list[str] = []
    sources = {"run": lambda: iter((SourceEntry("run", "1", first), SourceEntry("run", "2", second)))}
    submit = lambda path, reason: seen.append(path) or True
    walker = reconcile.Reconciler(submit, cursor.get, cursor.set, data_root=str(data),
                                  smart_sources=sources, drives=[], max_offers=1)

    assert walker() is False
    resumed = reconcile.Reconciler(submit, cursor.get, cursor.set, data_root=str(data),
                                   smart_sources=sources, drives=[], max_offers=1)
    assert resumed() is False
    assert resumed()
    assert seen == [first, second]


def test_restart_revisits_the_beginning_after_a_second_loss(tmp_path: Path) -> None:
    _file(tmp_path / "drive" / "a.exe")
    _file(tmp_path / "drive" / "b.exe")
    cursor = Cursor()
    seen: list[str] = []
    walker = _new(tmp_path, cursor, lambda path, reason: seen.append(path) or True, max_offers=1)

    assert walker() is False
    first = seen[0]
    walker.restart()
    assert json.loads(cursor.value or "")["phase"] == "smart"
    assert walker() is False
    assert seen == [first, first]


def test_time_budget_stops_a_pass_after_work_already_offered(tmp_path: Path) -> None:
    _file(tmp_path / "drive" / "a.exe")
    _file(tmp_path / "drive" / "b.exe")
    cursor = Cursor()
    now = [0.0]
    seen: list[str] = []

    def submit(path: str, reason: str) -> bool:
        seen.append(path)
        now[0] = 61.0
        return True

    walker = _new(tmp_path, cursor, submit, max_seconds=60, clock=lambda: now[0])
    assert walker() is False
    assert len(seen) == 1


def test_scope_gaps_are_counted_and_not_offered(tmp_path: Path) -> None:
    drive = tmp_path / "drive"
    drive.mkdir()
    data = tmp_path / "service-data"
    data.mkdir()
    cursor = Cursor()
    seen: list[str] = []
    sources = {"gaps": lambda: iter((SourceEntry("gaps", "cloud", reason="cloud_placeholder"),
                                     SourceEntry("gaps", "denied", reason="access_denied")))}
    walker = reconcile.Reconciler(lambda path, reason: seen.append(path) or True,
                                  cursor.get, cursor.set, data_root=str(data),
                                  smart_sources=sources, drives=[str(drive)])

    assert walker()
    assert seen == []
    assert walker.report()["gaps"]["cloud_placeholder"] == 1
    assert walker.report()["gaps"]["access_denied"] == 1
    assert walker.report()["finished"] and not walker.report()["complete"]


def test_deep_access_denial_is_counted_without_retry(tmp_path: Path,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    drive = tmp_path / "drive"
    drive.mkdir()
    cursor = Cursor()
    walker = _new(tmp_path, cursor, lambda path, reason: True)
    real_scandir = reconcile.os.scandir

    def denied(path: str):
        if str(path) == str(drive):
            raise PermissionError("harmless test denial")
        return real_scandir(path)

    monkeypatch.setattr(reconcile.os, "scandir", denied)
    assert walker()
    assert walker.report()["gaps"]["access_denied"] == 1


def test_a_new_debt_after_a_finished_walk_walks_again(tmp_path: Path) -> None:
    _file(tmp_path / "drive" / "a.exe")
    offered: list[str] = []
    walker = _new(tmp_path, Cursor(), lambda path, reason: offered.append(path) or True)
    assert walker() is True and len(offered) == 1
    assert walker() is True and len(offered) == 2
