"""A2: restricted, low-integrity scan worker in a Job Object (R13 §2, R13b P5).

Runs unelevated: the worker token is a restricted copy of the test process's
own token. As the LocalSystem service the same code starts from the service
token; that case is the owner's elevated acceptance check.
"""

from __future__ import annotations

import os
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="restricted workers need Windows")


def run(code: str, *, memory_limit: int = 256 * 1024 * 1024, timeout: float = 30.0) -> tuple[str, int | None]:
    from sentinel.service import worker

    agent = os.path.dirname(os.path.dirname(os.path.abspath(worker.__file__)))
    prelude = f"import sys; sys.path.insert(0, {os.path.dirname(agent)!r}); "
    w = worker.launch(["-c", prelude + code], memory_limit=memory_limit)
    try:
        out = w.stdout.read(4096).decode("utf-8", "replace")
        return out, w.wait(timeout)
    finally:
        w.kill()


FAKE_SERVICE_SID = "S-1-5-80-1111111111-2222222222-3333333333-4000000000-1234567890"


def restricting_sids(token: int) -> set[str]:
    import ctypes
    from ctypes import wintypes

    from sentinel.service import worker
    from sentinel.service.winpipe import _sid_string

    adv = worker._adv
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    needed = wintypes.DWORD()
    adv.GetTokenInformation(token, 11, None, 0, ctypes.byref(needed))  # TokenRestrictedSids
    buf = ctypes.create_string_buffer(needed.value)
    assert adv.GetTokenInformation(token, 11, buf, len(buf), ctypes.byref(needed))
    count = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0]
    entries = ctypes.cast(ctypes.addressof(buf) + 8, ctypes.POINTER(worker.SID_AND_ATTRIBUTES * count)).contents
    return {_sid_string(entry.Sid) for entry in entries}


def test_the_service_worker_token_is_restricted_to_what_the_runtime_grants_everyone():
    from sentinel.service import worker

    token = worker._restricted_low_token(FAKE_SERVICE_SID)
    try:
        assert restricting_sids(token) == {*worker.RESTRICTING_SIDS, FAKE_SERVICE_SID}
    finally:
        worker._k32.CloseHandle(token)
    # Portable mode keeps the user's own identity: its files grant nobody else.
    token = worker._restricted_low_token(None)
    try:
        assert restricting_sids(token) == set()
    finally:
        worker._k32.CloseHandle(token)


def test_the_private_desktop_is_made_once_on_a_station_windows_named():
    from sentinel.service import worker

    first = worker._private_desktop()
    assert first == worker._private_desktop()
    station, desktop = first.split("\\")
    assert station.startswith("Service-0x") and desktop == "Worker"
    assert all(worker._desktop_handles)


@pytest.mark.parametrize(("sid", "attempts"), [
    # Unnamed, SYSTEM would get the station every LocalSystem service shares.
    ("S-1-5-18", ["SentinelGuardWorker"]),
    ("S-1-5-21-1-2-3-1001", ["SentinelGuardWorker", None]),
])
def test_the_service_never_falls_back_to_the_shared_station(monkeypatch, sid, attempts):
    import ctypes
    from types import SimpleNamespace

    from sentinel.service import winpipe, worker

    asked = []

    def refused(name, flags, access, attrs):
        asked.append(name)
        ctypes.set_last_error(5)
        return 0

    monkeypatch.setattr(worker, "_desktop", None)
    monkeypatch.setattr(worker._u32, "CreateWindowStationW", refused)
    monkeypatch.setattr(winpipe, "current_process_caller", lambda: SimpleNamespace(sid=sid))
    with pytest.raises(worker.WorkerError):
        worker._private_desktop()
    assert asked == attempts


def test_a_service_worker_starts_detached_on_the_private_desktop(monkeypatch):
    from sentinel.service import worker

    seen = {}

    def refuse(token, exe, cmdline, pa, ta, inherit, flags, env, cwd, si, pi):
        seen["flags"], seen["desktop"] = flags, si._obj.StartupInfo.lpDesktop
        return 0

    monkeypatch.setattr(worker, "_private_desktop", lambda: "Station\\Worker")
    monkeypatch.setattr(worker._adv, "CreateProcessAsUserW", refuse)
    with pytest.raises(worker.WorkerError):
        worker.launch(["-c", "0"], service_sid=FAKE_SERVICE_SID)
    assert seen["desktop"] == "Station\\Worker"
    assert seen["flags"] & worker.DETACHED_PROCESS and not seen["flags"] & 0x08000000
    seen.clear()
    with pytest.raises(worker.WorkerError):
        worker.launch(["-c", "0"])
    assert seen["desktop"] is None


def test_worker_runs_at_low_integrity_without_admin():
    out, code = run("from sentinel.service import winpipe; c = winpipe.current_process_caller(); "
                    "print(c.integrity, c.is_admin)")
    assert code == 0, out
    assert out.split() == ["low", "False"]


def test_worker_can_read_the_file_to_scan_but_cannot_write_beside_it(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"harmless sample")
    out, code = run(
        f"data = open({str(target)!r}, 'rb').read(); print('read', len(data));\n"
        f"try:\n    open({str(tmp_path / 'dropped.txt')!r}, 'wb').write(b'x'); print('wrote')\n"
        "except PermissionError:\n    print('denied')")
    assert code == 0, out
    assert out.split() == ["read", "15", "denied"]
    assert not (tmp_path / "dropped.txt").exists()


def test_worker_cannot_start_other_processes():
    out, code = run(
        "import subprocess, sys\n"
        "try:\n    subprocess.run([sys.executable, '-c', '0'], timeout=10); print('spawned')\n"
        "except OSError:\n    print('blocked')")
    assert code == 0, out
    assert out.strip() == "blocked"


def test_worker_memory_is_capped():
    out, code = run(
        "try:\n    b = bytearray(400 * 1024 * 1024); print('allocated')\n"
        "except MemoryError:\n    print('capped')",
        memory_limit=128 * 1024 * 1024)
    assert "allocated" not in out
    assert out.strip() == "capped" or code not in (0, None)


def test_worker_environment_does_not_leak_the_parents(monkeypatch):
    monkeypatch.setenv("SG_PARENT_ONLY_SETTING", "secret")
    monkeypatch.setenv("PYTHONPATH", r"C:\planted")
    out, code = run("import os; print(sorted(k.upper() for k in os.environ))")
    assert code == 0, out
    assert "SG_PARENT_ONLY_SETTING" not in out and "PYTHONPATH" not in out


def test_kill_ends_a_busy_worker_promptly():
    from sentinel.service import worker

    w = worker.launch(["-c", "import time; time.sleep(15)"])
    entered = threading.Event()
    output = []

    def blocked_reader() -> None:
        entered.set()
        output.append(w.stdout.read(1))

    reader = threading.Thread(target=blocked_reader, daemon=True)
    reader.start()
    assert entered.wait(2)
    time.sleep(0.1)
    start = time.monotonic()
    w.kill()
    reader.join(2)
    assert time.monotonic() - start < 10
    assert not reader.is_alive() and output == [b""]
    assert w._process == 0
