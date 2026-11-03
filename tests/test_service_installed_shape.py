"""Exercise a restricted worker from a staged, protected runtime on Windows."""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel.gate_v2.content import BoundReader
from sentinel.gate_v2.contract import ScanRequest
from sentinel.service import installer, worker, workerclient
from sentinel.service.protocol import MAX_FRAME, MAX_RULES_FRAME, read_frame, write_frame
from sentinel.service.winpipe import current_process_caller

pytestmark = pytest.mark.skipif(os.name != "nt", reason="installed worker shape needs Windows")

SERVICE_SID = "S-1-5-80-1111111111-2222222222-3333333333-4000000000-1234567890"


class _NeverCancel:
    def cancelled(self) -> bool:
        return False


@pytest.fixture(scope="module")
def installed_shape(tmp_path_factory):
    root = tmp_path_factory.mktemp("installed_shape")
    snapshot = root / "snapshot"
    runtime = root / "runtime"
    installer.snapshot_runtime(snapshot)
    installer.write_runtime(installer.plan_runtime(snapshot), runtime)
    me = current_process_caller().sid
    sddl = (f"O:{me}G:{me}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
            f"(A;OICI;FA;;;{me})(A;OICI;FRFX;;;BU)(A;OICI;FRFX;;;{SERVICE_SID})")
    scm = installer.WindowsScm()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(installer, "verify_path_acl", lambda *args, **kwargs: None)
        patch.setattr(installer, "enable_privilege", lambda name: None)
        for path in installer.walk_no_reparse(runtime):
            scm._secure_path(path, sddl, directory=path.is_dir())
    worker._private_desktop()
    return root, runtime, scm, me


def _launch(runtime: Path) -> worker.Worker:
    return worker.launch(["-m", "sentinel.service.workermain"], python=str(runtime / "python.exe"),
                         cwd=str(runtime), service_sid=SERVICE_SID)


def _exchange(proc: worker.Worker, request_id: int, op: str, args: dict, *,
              limit: int = MAX_FRAME, timeout: float = 30.0) -> dict:
    write_frame(proc.stdin, {"id": request_id, "op": op, "args": args}, limit=limit)
    replies: queue.Queue[dict | None | Exception] = queue.Queue(maxsize=1)

    def receive() -> None:
        try:
            replies.put(read_frame(proc.stdout))
        except Exception as error:
            replies.put(error)

    threading.Thread(target=receive, daemon=True).start()
    try:
        reply = replies.get(timeout=timeout)
    except queue.Empty:
        pytest.fail(f"worker did not answer {op} within {timeout} seconds")
    if isinstance(reply, Exception):
        raise reply
    assert reply is not None and reply["id"] == request_id and reply["ok"], reply
    return reply["result"]


def _scan(proc: worker.Worker, path: Path, request_id: int, engine: str) -> dict:
    reader = BoundReader.measure_path(str(path), max_bytes=1 << 20, cancel=_NeverCancel())
    try:
        request = ScanRequest(2, "scan", "installed-shape", path.name, None, "test", "single_file",
                              "evidence-v1", "evidence-v1", time.monotonic_ns() + 60_000_000_000,
                              None, False)
        session = workerclient.WorkerSession()
        session._proc = proc
        handle = reader.os_handle()
        assert handle is not None
        duplicated = session._duplicate(handle)
        return _exchange(proc, request_id, "scan", {
            "engine": engine, "request": request.to_dict(),
            "identity": replace(reader.identity, canonical_path=None).to_dict(),
            "handle": duplicated,
        })["engine_result"]
    finally:
        reader.close()


def test_installed_worker_initializes_every_engine(installed_shape):
    _, runtime, _, _ = installed_shape
    proc = _launch(runtime)
    try:
        result = _exchange(proc, 1, "init", {})
        assert result["engines"] == ["core", "json_rules", "lnk", "signer", "yara_x"]
    finally:
        proc.kill()


def test_installed_worker_scans_a_duplicated_measured_handle(installed_shape):
    root, runtime, _, _ = installed_shape
    sample = root / "harmless.txt"
    sample.write_bytes(b"ordinary harmless text")
    proc = _launch(runtime)
    try:
        _exchange(proc, 1, "init", {})
        result = _scan(proc, sample, 2, "core")
        assert result["status"] == "completed"
        assert result["file_id"] == "installed-shape"
    finally:
        proc.kill()


def test_installed_worker_cannot_read_private_data_or_write_to_code(installed_shape):
    root, runtime, scm, me = installed_shape
    private = root / "private.txt"
    private.write_bytes(b"private harmless text")
    private_sddl = f"O:{me}G:{me}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{me})"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(installer, "verify_path_acl", lambda *args, **kwargs: None)
        scm._secure_path(private, private_sddl, directory=False)
    readable = runtime / "app" / "sentinel" / "__init__.py"
    beside = readable.with_name("installed_shape_drop.txt")
    code = ("from pathlib import Path\n"
            f"private = Path({json.dumps(str(private))})\n"
            f"readable = Path({json.dumps(str(readable))})\n"
            f"beside = Path({json.dumps(str(beside))})\n"
            "try:\n    private.read_bytes(); print('private:read')\n"
            "except PermissionError:\n    print('private:denied')\n"
            "print('code:read' if readable.read_bytes() is not None else 'code:empty')\n"
            "try:\n    beside.write_bytes(b'harmless'); print('code:written')\n"
            "except PermissionError:\n    print('code:denied')\n")
    proc = worker.launch(["-c", code], python=str(runtime / "python.exe"), cwd=str(runtime),
                         service_sid=SERVICE_SID)
    try:
        output = proc.stdout.read().decode("utf-8", "replace")
        assert proc.wait(30) == 0, output
        assert output.splitlines() == ["private:denied", "code:read", "code:denied"]
        assert not beside.exists()
    finally:
        proc.kill()


def test_large_rules_frame_reaches_the_installed_worker(installed_shape):
    root, runtime, _, _ = installed_shape
    source = "\n".join(
        f'rule harmless_{number} {{ strings: $a = "sentinel-shape-{number:06d}-never-present" condition: $a }}'
        for number in range(12_000))
    assert len(source.encode("utf-8")) > MAX_FRAME
    sample = root / "large-rules-harmless.txt"
    sample.write_bytes(b"ordinary harmless text")
    proc = _launch(runtime)
    try:
        result = _exchange(proc, 1, "init", {"json_packs": [], "yara_sources": [["big", "big.yar", source]]},
                           limit=MAX_RULES_FRAME, timeout=120.0)
        assert "yara_x" in result["engines"]
        assert _scan(proc, sample, 2, "yara_x")["status"] == "completed"
    finally:
        proc.kill()
