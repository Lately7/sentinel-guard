"""M8 + A4: what a smart or deep scan covers, and what it says it could not look at."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel import config, scanjob
from sentinel.gate_v2 import scope
from sentinel.gate_v2.scope import SourceEntry, discover, walk_folder


def entries(*items: SourceEntry):
    return lambda: iter(items)


def make(tmp_path: Path, name: str, body: bytes = b"x") -> str:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return str(path)


def test_one_scan_per_file_whatever_the_number_of_names(tmp_path):
    first = make(tmp_path, "a.bin")
    second = str(tmp_path / "b.bin")
    os.link(first, second)
    found = discover("smart", {"run": entries(SourceEntry("run", "1", first), SourceEntry("run", "2", first)),
                               "tasks": entries(SourceEntry("task", "t", second))})
    assert [t.path for t in found] == [first]
    assert found.report.duplicates == 2 and found.report.complete


def test_missing_key_is_not_a_gap_but_denied_is():
    quiet = discover("smart", {"r": entries(SourceEntry("r", "k", reason="missing_key"))})
    assert list(quiet) == [] and quiet.report.complete
    denied = discover("smart", {"r": entries(SourceEntry("r", "k", reason="access_denied"))})
    assert list(denied) == [] and not denied.report.complete
    assert denied.report.gaps[0].reason == "access_denied"


def test_a_source_that_dies_is_a_gap_and_the_others_still_run(tmp_path):
    def broken():
        raise PermissionError("no")
        yield

    def crashing():
        raise OSError("disk")
        yield

    good = make(tmp_path, "a.bin")
    found = discover("smart", {"bad": broken, "worse": crashing, "fine": entries(SourceEntry("f", "1", good))})
    assert [t.path for t in found] == [good]
    assert found.report.reasons["access_denied"] == 1 and found.report.reasons["source_error"] == 1


def test_our_own_data_is_excluded_by_identity_not_by_spelling(tmp_path):
    data = tmp_path / "Data"
    inside = make(data, "quarantine/x.qbin")
    link = tmp_path / "alias"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(data)], check=True, stdout=subprocess.DEVNULL)
    found = discover("smart", {"f": entries(SourceEntry("f", "1", inside),
                                            SourceEntry("f", "2", str(link / "quarantine" / "x.qbin")))},
                     data_root=str(data))
    assert list(found) == []
    assert found.report.reasons["excluded_data"] == 2 and found.report.complete


def test_data_folder_we_cannot_identify_stops_the_scan_loudly(tmp_path):
    found = discover("smart", {"f": entries(SourceEntry("f", "1", make(tmp_path, "a")))},
                     data_root=str(tmp_path / "nope"))
    assert list(found) == [] and found.report.gaps[0].reason == "identity_error"


def test_junction_denied_folder_and_depth_are_in_the_report(tmp_path):
    root = tmp_path / "root"
    make(root, "keep.bin")
    make(root, "a/b/c/deep.bin")
    (tmp_path / "other").mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "jump"), str(tmp_path / "other")],
                   check=True, stdout=subprocess.DEVNULL)
    seen = list(walk_folder(str(root), "watched", max_depth=2))
    assert {"reparse_skipped", "depth_limit"} <= {e.reason for e in seen}
    assert any(e.path and e.path.endswith("keep.bin") for e in seen)
    assert not any(e.path and "other" in e.path for e in seen), "a junction leaves the chosen tree"


def test_a_tree_past_the_old_path_limit_is_still_walked(tmp_path):
    folder = "\\\\?\\" + str(tmp_path)
    for _ in range(14):
        folder += "\\" + "d" * 24
        os.mkdir(folder)
    with open(folder + "\\deep.bin", "wb") as stream:
        stream.write(b"x")
    seen = [e for e in walk_folder(str(tmp_path), "watched") if e.path]
    assert any(e.path.endswith("deep.bin") for e in seen)
    found = discover("deep", {"d": lambda: walk_folder(str(tmp_path), "watched")})
    assert any(t.path.endswith("deep.bin") for t in found)


def test_limits_stop_the_scan_and_say_so(tmp_path):
    files = [make(tmp_path, f"{i}.bin", b"12345") for i in range(5)]
    source = {"f": entries(*(SourceEntry("f", str(i), p) for i, p in enumerate(files)))}
    capped = discover("smart", source, max_entries=2)
    assert len(list(capped)) == 2 and capped.report.reasons["entry_limit"] == 1

    now = [0.0]
    timed = discover("smart", source, max_seconds=1, clock=lambda: now[0])
    assert next(timed).path == files[0]
    now[0] = 5.0
    assert list(timed) == [] and timed.report.reasons["time_limit"] == 1

    bytes_capped = discover("smart", source, max_bytes=7)
    assert len(list(bytes_capped)) == 1 and bytes_capped.report.reasons["byte_limit"] == 1


def test_a_deep_scan_resumes_after_its_cursor(tmp_path):
    files = [make(tmp_path, f"{i}.bin") for i in range(4)]
    source = {"f": entries(*(SourceEntry("f", str(i), p) for i, p in enumerate(files)))}
    first = discover("deep", source)
    assert next(first).path == files[0] and next(first).path == files[1]
    second = discover("deep", source, cursor=first.report.cursor)
    assert [t.path for t in second] == files[2:]
    assert second.report.complete


def test_a_lost_cursor_costs_time_not_coverage(tmp_path):
    files = [make(tmp_path, f"{i}.bin") for i in range(3)]
    source = {"f": entries(*(SourceEntry("f", str(i), p) for i, p in enumerate(files)))}
    found = discover("deep", source, cursor="f\0gone-file")
    assert [t.path for t in found] == files
    assert found.report.reasons["cursor_lost"] == 1


def test_a_vanished_file_is_reported(tmp_path):
    found = discover("smart", {"f": entries(SourceEntry("f", "1", str(tmp_path / "gone.bin")))})
    assert list(found) == [] and found.report.reasons["vanished"] == 1


def test_gaps_kept_in_memory_are_bounded_but_the_count_is_not():
    many = [SourceEntry("f", str(i), reason="access_denied") for i in range(50)]
    found = discover("smart", {"f": entries(*many)}, max_gaps=5)
    list(found)
    assert len(found.report.gaps) == 5 and found.report.gap_count == 50


def test_task_xml_yields_programs_and_their_arguments(tmp_path):
    program = make(tmp_path, "up date.exe")
    script = make(tmp_path, "payload.ps1")
    xml = f"""
    <Tasks>
    <!-- \\One -->
    <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo><URI>\\One</URI></RegistrationInfo>
      <Actions><Exec><Command>{program}</Command><Arguments>-File {script}</Arguments></Exec></Actions>
    </Task>
    <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo><URI>\\ComOnly</URI></RegistrationInfo>
      <Actions><ComHandler><ClassId>{{00000000-0000-0000-0000-000000000000}}</ClassId></ComHandler></Actions>
    </Task>
    </Tasks>"""
    seen = list(scope.task_actions(xml))
    assert {e.path for e in seen if e.path} == {program, script}
    assert [e.reason for e in seen if e.path is None] == ["no_executable_action"]


def test_broken_task_output_is_a_gap():
    assert [e.reason for e in scope.task_actions("<Tasks><oops")] == ["source_error"]
    denied = SimpleNamespace(returncode=1, stdout=b"", stderr=b"")
    assert [e.reason for e in scope.scheduled_tasks(run=lambda *a, **k: denied)] == ["access_denied"]
    huge = SimpleNamespace(returncode=0, stdout=b"x" * (scope.MAX_TASK_XML + 1), stderr=b"")
    assert [e.reason for e in scope.scheduled_tasks(run=lambda *a, **k: huge)] == ["byte_limit"]

    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired("schtasks", 1)

    assert [e.reason for e in scope.scheduled_tasks(run=slow)] == ["timed_out"]


@pytest.mark.parametrize(("value", "expected"), [
    (r"\SystemRoot\System32\drivers\x.sys", r"C:\Win\System32\drivers\x.sys"),
    (r"system32\DRIVERS\y.sys", r"C:\Win\system32\DRIVERS\y.sys"),
    (r"\??\C:\Tools\z.sys", r"C:\Tools\z.sys"),
    (r'"C:\Program Files\a.exe" -k', r'"C:\Program Files\a.exe" -k'),
])
def test_service_image_paths_become_win32_paths(value, expected):
    assert scope.image_path(value, r"C:\Win") == expected


def test_shared_service_dll_is_found_not_just_svchost(tmp_path):
    dll = make(tmp_path, "evil.dll")
    host = make(tmp_path, "svchost.exe")

    class Key:
        def __init__(self, name: str) -> None:
            self.name = name

        def __enter__(self):
            return self

        def __exit__(self, *exc: object) -> None:
            pass

    class Reg:
        HKEY_LOCAL_MACHINE = "hklm"
        KEY_READ = 1

        def OpenKey(self, parent, name, *rest):
            return Key(name)

        def EnumKey(self, parent, index):
            if index:
                raise OSError
            return "Bad"

        def QueryValueEx(self, key, value):
            return (f'"{host}" -k netsvcs' if value == "ImagePath" else dll), 1

    assert {e.path for e in scope.service_images(Reg(), system_root="C:\\Win") if e.path} == {host, dll}


def test_unelevated_wmi_is_a_gap_because_its_empty_answer_means_nothing():
    def never(*args, **kwargs):
        raise AssertionError("not asked")

    assert [e.reason for e in scope.wmi_consumers(elevated=lambda: False, run=never)] == ["needs_admin"]


def test_elevated_wmi_lists_commands_and_flags_script_consumers(tmp_path):
    program = make(tmp_path, "tool.exe")
    answer = SimpleNamespace(returncode=0, stdout=f"C {program}\nS FilterKiller\n".encode(), stderr=b"")
    seen = list(scope.wmi_consumers(elevated=lambda: True, run=lambda *a, **k: answer))
    assert [e.path for e in seen if e.path] == [program]
    assert [e.reason for e in seen if not e.path] == ["script_consumer"]
    noisy = SimpleNamespace(returncode=0, stdout=b"", stderr=b"Access denied")
    assert [e.reason for e in scope.wmi_consumers(elevated=lambda: True, run=lambda *a, **k: noisy)] == ["access_denied"]


def test_every_entry_kind_on_this_machine_runs_without_raising(tmp_path):
    # The real sources, read-only: whatever this account cannot see must be a gap.
    found = discover("smart", scope.windows_sources("smart", [str(tmp_path)]), max_seconds=60)
    targets = list(found)
    assert targets, "something runs on this machine"
    assert found.report.reasons["needs_admin"] or found.report.reasons["script_consumer"] is not None
    assert found.report.entries >= len(targets)


def test_scan_job_reports_what_it_could_not_look_at(db, scanner, tmp_path):
    good = make(tmp_path, "a.bin")
    found = discover("smart", {"f": entries(SourceEntry("f", "1", good), SourceEntry("f", "2", reason="access_denied"))})
    done: list[object] = []
    job = scanjob.ScanJob(scanner, db, config.Settings(), [], "t", on_done=done.append, found=found).start()
    job.join(30)
    assert job.progress.scanned == 1 and job.progress.uncovered == {"access_denied": 1}
    assert done


def test_cancel_stops_a_discovery_scan(db, scanner, tmp_path):
    files = [make(tmp_path, f"{i}.bin") for i in range(50)]

    def slowly():
        for i, path in enumerate(files):
            time.sleep(0.01)
            yield SourceEntry("f", str(i), path)

    job = scanjob.ScanJob(scanner, db, config.Settings(), [], "t", found=discover("smart", {"f": slowly}))
    job.cancel()
    job.start().join(30)
    assert job.progress.scanned < 50 and job.progress.cancelled
