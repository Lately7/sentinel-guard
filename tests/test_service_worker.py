"""A2: restricted, low-integrity scan worker in a Job Object (R13 §2, R13b P5).

Runs unelevated: the worker token is a restricted copy of the test process's
own token. As the LocalSystem service the same code starts from the service
token; that case is the owner's elevated acceptance check.
"""

from __future__ import annotations

import os
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

    w = worker.launch(["-c", "import time; time.sleep(60)"])
    start = time.monotonic()
    w.kill()
    assert time.monotonic() - start < 10
    assert w._process == 0
