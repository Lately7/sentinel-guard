"""Agent failure recovery and bounded file-state checks."""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel import quarantine
from sentinel.gate_v2.content import BoundReader
from sentinel.gate_v2.contract import ScanRequest, VerdictCode
from sentinel.gate_v2.core import CoreAdapter
from sentinel.gate_v2.identity import measure
from sentinel.gate_v2.orchestrator import scan, scan_many


def request(path: Path) -> ScanRequest:
    return ScanRequest(2, "edge", "file", str(path), None, "test", "single_file",
                       "evidence-v1", "evidence-v1", time.monotonic_ns() + 5_000_000_000,
                       None, False)


def test_exact_file_limit_and_one_byte_over(tmp_path: Path) -> None:
    # R11 invariant 8: the byte bound is inclusive and rejects the next byte.
    path = tmp_path / "ordinary.bin"
    path.write_bytes(b"harmless")
    assert measure(str(path), max_bytes=8).ok
    assert measure(str(path), max_bytes=7).code == "TOO_LARGE"


def test_sparse_huge_logical_file_is_rejected_before_read(tmp_path: Path) -> None:
    # R11 invariant 8: logical size, even with no allocated blocks, respects the byte cap.
    path = tmp_path / "sparse.bin"
    with path.open("wb") as stream:
        stream.truncate(8 * 1024 * 1024 * 1024)
    assert measure(str(path), max_bytes=1024).code == "TOO_LARGE"


def test_reader_close_is_idempotent(tmp_path: Path) -> None:
    # R11 invariant 8: closing a held reader twice must not leave a live handle or raise.
    path = tmp_path / "ordinary.bin"
    path.write_bytes(b"harmless")
    class NeverCancel:
        def cancelled(self) -> bool:
            return False
    reader = BoundReader.measure_path(str(path), max_bytes=100, cancel=NeverCancel())
    reader.close()
    reader.close()
    assert reader.os_handle() is None


def test_four_workers_scan_one_file_without_generation_split(tmp_path: Path) -> None:
    # R11 invariant 2: simultaneous readers must bind to the same harmless generation.
    path = tmp_path / "ordinary.bin"
    path.write_bytes(b"harmless synthetic bytes")
    requests = [replace(request(path), file_id=f"file-{i}") for i in range(4)]
    decisions = scan_many(requests, adapters=[CoreAdapter()], gate_generation="edge",
                          auto_quarantine=False, workers=4)
    assert len(decisions) == 4
    assert all(item.verdict is VerdictCode.CLEAN for item in decisions)
    assert len({item.identity.sha256 for item in decisions if item.identity}) == 1


def test_adapter_baseexception_becomes_typed_failure() -> None:
    # R11 invariant 7: an adapter failure must leave a typed stage result.
    class AdapterFailure(BaseException):
        pass
    class Broken(CoreAdapter):
        def scan_bound(self, request, measured, cancel, reader):
            raise AdapterFailure()
    req = ScanRequest(2, "edge", "file", None, b"harmless", "test", "memory",
                      "evidence-v1", "evidence-v1", time.monotonic_ns() + 5_000_000_000,
                      None, False)
    decision = scan(req, adapters=[Broken()], gate_generation="edge", auto_quarantine=False)
    assert decision.verdict is VerdictCode.UNKNOWN
    assert decision.engine_results[0].readiness_code == "ADAPTER_ERROR"


def test_quarantine_disk_full_rolls_back_claim_and_blob(
    tmp_path: Path, db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # R11 invariant 9: a failed automatic action rolls its claimed file back.
    path = tmp_path / "original.bin"
    body = b"harmless synthetic bytes"
    path.write_bytes(body)
    original_copy = quarantine._copy_xor
    def full_disk(src: Path, dest: Path) -> str:
        dest.write_bytes(b"partial encoded blob")
        raise OSError(28, "synthetic disk full")
    monkeypatch.setattr(quarantine, "_copy_xor", full_disk)
    with pytest.raises(quarantine.QuarantineError):
        quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(body).hexdigest()})
    assert path.read_bytes() == body
    assert not list(tmp_path.glob("*.claim"))
    assert not list(quarantine.config.quarantine_dir().glob("*.qbin"))
    monkeypatch.setattr(quarantine, "_copy_xor", original_copy)


def test_restore_tampered_blob_keeps_item_and_removes_output(tmp_path: Path, db) -> None:
    # R11 invariant 13: corrupt stored bytes cannot be restored or trusted.
    path = tmp_path / "original.bin"
    body = b"harmless synthetic bytes"
    path.write_bytes(body)
    qid = quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(body).hexdigest()})
    blob = quarantine.config.quarantine_dir() / f"{qid}.qbin"
    blob.write_bytes(b"tampered inert data")
    with pytest.raises(quarantine.QuarantineError, match="hash mismatch"):
        quarantine.restore(db, qid, trust=False)
    assert db.quarantine_item(qid) is not None
    assert not path.exists()


@pytest.mark.skipif(os.name != "nt", reason="directory junction/symlink behavior requires Windows")
def test_restore_rejects_replaced_parent_directory(tmp_path: Path, db) -> None:
    # R11 invariant 13: restore is bound to its original folder, not a later reparse target.
    parent = tmp_path / "original-folder"
    parent.mkdir()
    path = parent / "ordinary.bin"
    body = b"harmless synthetic bytes"
    path.write_bytes(body)
    qid = quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(body).hexdigest()})
    parent.rmdir()
    redirected = tmp_path / "redirected-folder"
    redirected.mkdir()
    try:
        parent.symlink_to(redirected, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")
    with pytest.raises(quarantine.QuarantineError):
        quarantine.restore(db, qid, trust=False)
    assert not (redirected / "ordinary.bin").exists()
    assert db.quarantine_item(qid) is not None


def test_two_quarantine_items_with_one_original_path_restore_distinctly(tmp_path: Path, db) -> None:
    # R11 invariant 13: restoring one generation cannot overwrite another.
    path = tmp_path / "ordinary.bin"
    first = b"harmless generation one"
    second = b"harmless generation two"
    path.write_bytes(first)
    first_id = quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(first).hexdigest()})
    path.write_bytes(second)
    second_id = quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(second).hexdigest()})
    first_target = quarantine.restore(db, first_id, trust=False)
    second_target = quarantine.restore(db, second_id, trust=False)
    assert first_target != second_target
    assert {first_target.read_bytes(), second_target.read_bytes()} == {first, second}


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate data streams require Windows")
def test_payload_in_alternate_stream_is_not_certified_clean(tmp_path: Path) -> None:
    # R11 invariant 7: an unenumerated NTFS stream must not make a file trusted clean.
    base = tmp_path / "ordinary.txt"
    base.write_bytes(b"harmless base")
    stream_path = Path(str(base) + ":side")
    try:
        stream_path.write_bytes(b"harmless stream")
    except OSError as exc:
        pytest.skip(f"NTFS alternate data streams unavailable: {exc}")
    decision = scan(request(base), adapters=[CoreAdapter()], gate_generation="edge", auto_quarantine=False)
    assert not decision.trusted_clean


@pytest.mark.skipif(os.name != "nt", reason="NTFS hard links require Windows")
def test_hard_link_aliases_have_same_identity(tmp_path: Path) -> None:
    # R11 invariant 2: path aliases to one file share the measured volume and file ID.
    original = tmp_path / "original.bin"
    alias = tmp_path / "alias.bin"
    original.write_bytes(b"harmless")
    try:
        os.link(original, alias)
    except OSError as exc:
        pytest.skip(f"NTFS hard links unavailable: {exc}")
    first = measure(str(original)).identity
    second = measure(str(alias)).identity
    assert first and second
    assert (first.volume_serial, first.file_id_hex, first.sha256) == (
        second.volume_serial, second.file_id_hex, second.sha256)


@pytest.mark.skipif(os.name != "nt", reason="Windows symlink loops require Windows reparse points")
def test_symlink_loop_is_typed_unreadable(tmp_path: Path) -> None:
    # R11 invariant 7: a reparse loop is a typed omission, not an exception or clean file.
    first = tmp_path / "first"
    second = tmp_path / "second"
    try:
        first.symlink_to(second)
        second.symlink_to(first)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    decision = scan(request(first), adapters=[CoreAdapter()], gate_generation="edge",
                    auto_quarantine=False)
    assert decision.verdict is VerdictCode.UNKNOWN
    assert not decision.trusted_clean


@pytest.mark.skipif(os.name != "nt", reason="Windows Unicode path behavior requires NTFS")
@pytest.mark.parametrize("name", ["right\u202eto\u202c.txt", "combining-e\u0301.txt", "zero\u200bwidth.txt"])
def test_unicode_control_names_return_typed_decision(tmp_path: Path, name: str) -> None:
    # R11 invariant 7: odd Unicode names remain bounded inputs to the scan contract.
    path = tmp_path / name
    try:
        path.write_bytes(b"harmless synthetic bytes")
    except OSError as exc:
        pytest.skip(f"NTFS Unicode name unavailable: {exc}")
    decision = scan(request(path), adapters=[CoreAdapter()], gate_generation="edge",
                    auto_quarantine=False)
    assert decision.identity is not None
    assert decision.verdict in (VerdictCode.CLEAN, VerdictCode.SUSPICIOUS)
