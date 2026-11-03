"""RED6 content and archive regressions using only harmless test data."""

from __future__ import annotations

import io
import mmap
import struct
import time
import zipfile
from pathlib import Path

import pytest

from conftest import MARKER
from sentinel.gate_v2 import archive, identity
from sentinel.gate_v2.contract import ScanRequest, VerdictCode
from sentinel.gate_v2.core import CoreAdapter
from sentinel.gate_v2.orchestrator import scan
from sentinel.gate_v2.rules import JsonRulesAdapter
from sentinel.engine.scanner import Scanner


class NeverCancel:
    def cancelled(self) -> bool:
        return False


def _request(data: bytes) -> ScanRequest:
    return ScanRequest(2, "red6-orphan", "file", None, data, "test", "memory",
                       "evidence-v1", "evidence-v1", time.monotonic_ns() + 5_000_000_000,
                       None, False)


# A downloaded ZIP hides a marker in an orphaned compressed local entry and receives a clean result.
def test_orphan_local_zip_entry_is_not_certified_clean(tmp_path: Path, marker_rule: Path) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("payload.txt", MARKER * 16)
    ordinary = output.getvalue()
    local_only = ordinary[:ordinary.index(b"PK\x01\x02")]
    # An empty directory is syntactically valid, while the earlier local record
    # remains in the byte stream for local-header-based recovery tools.
    empty_directory = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 0, 0,
                                  0, len(local_only), 0)
    crafted = local_only + empty_directory
    assert MARKER not in crafted
    assert archive.is_zip(crafted)
    with zipfile.ZipFile(io.BytesIO(crafted)) as parsed:
        assert parsed.infolist() == []
    rules = JsonRulesAdapter.from_directories(marker_rule.parent)
    decision = scan(_request(crafted), adapters=[CoreAdapter(name="sample.zip"), rules],
                    gate_generation="red6", auto_quarantine=False)
    assert decision.verdict is not VerdictCode.CLEAN
    assert not decision.trusted_clean


# A local process changes equal-size mapped bytes between hash chunks, yielding a hash of no file generation.
def test_same_size_change_during_measurement_is_rejected(tmp_path: Path) -> None:
    first = MARKER.ljust(64, b"A")
    initial = first + b"B" * 64
    final = b"C" * 64 + MARKER.ljust(64, b"D")
    path = tmp_path / "changing.bin"
    path.write_bytes(initial)
    with path.open("r+b", buffering=0) as writable:
        mapped = mmap.mmap(writable.fileno(), len(initial), access=mmap.ACCESS_WRITE)
    try:
        def change_after_first_chunk(count: int) -> None:
            if count == 64:
                mapped[:] = final
                mapped.flush()

        with path.open("rb", buffering=0) as stream:
            result = identity.measure_stream(stream, str(path), max_bytes=128,
                                             cancel=NeverCancel(), chunk_size=64,
                                             between_chunks=change_after_first_chunk,
                                             ignore_times=True)
        assert path.read_bytes() == final
        assert result.code == "CHANGED"
    finally:
        mapped.close()


# A downloaded file puts the marker in an unread middle span yet the displayed label says clean.
def test_fixed_partial_middle_gap_is_not_labeled_clean(
    tmp_path: Path, scanner: Scanner, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sentinel import config

    monkeypatch.setattr(config, "MAX_DEEP_SCAN_BYTES", 64)
    path = tmp_path / "payload.bin"
    path.write_bytes(b"A" * 100 + MARKER + b"B" * 100)
    verdict = scanner.scan_file(path, use_cache=False)
    assert verdict.label != "clean"
