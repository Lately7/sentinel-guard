"""RED6 content and archive regressions using only harmless test data."""

from __future__ import annotations

import io
import mmap
import os
import struct
import time
import zipfile
from pathlib import Path

import pytest

from conftest import MARKER
from sentinel.gate_v2 import archive
from sentinel.gate_v2.content import BoundReader, ContentError
from sentinel.gate_v2.contract import ScanRequest, VerdictCode
from sentinel.gate_v2.core import CoreAdapter
from sentinel.gate_v2.orchestrator import scan
from sentinel.gate_v2.rules import JsonRulesAdapter


class NeverCancel:
    def cancelled(self) -> bool:
        return False


def _request(data: bytes) -> ScanRequest:
    return ScanRequest(2, "red6-orphan", "file", None, data, "test", "memory",
                       "evidence-v1", "evidence-v1", time.monotonic_ns() + 5_000_000_000,
                       None, False)


# A downloaded ZIP hides a marker in an orphaned compressed local entry and receives a clean result.
def test_orphan_local_zip_entry_is_not_certified_clean(marker_rule: Path) -> None:
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
    assert any("ORPHAN_LOCAL_HEADER" in result.coverage.object_reasons
               for result in decision.engine_results)


def test_orphan_local_zip_entry_before_listed_member_is_not_certified_clean(marker_rule: Path) -> None:
    orphan = io.BytesIO()
    with zipfile.ZipFile(orphan, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("payload.txt", MARKER * 16)
    local_only = orphan.getvalue().split(b"PK\x01\x02", 1)[0]
    listed = io.BytesIO()
    with zipfile.ZipFile(listed, "w") as bundle:
        bundle.writestr("readme.txt", b"harmless child")
    crafted = local_only + listed.getvalue()

    assert MARKER not in crafted
    with zipfile.ZipFile(io.BytesIO(crafted)) as parsed:
        assert [info.filename for info in parsed.infolist()] == ["readme.txt"]
    rules = JsonRulesAdapter.from_directories(marker_rule.parent)
    decision = scan(_request(crafted), adapters=[CoreAdapter(name="sample.zip"), rules],
                    gate_generation="red6", auto_quarantine=False)
    assert decision.verdict is not VerdictCode.CLEAN
    assert not decision.trusted_clean
    assert any("ORPHAN_LOCAL_HEADER" in result.coverage.object_reasons
               for result in decision.engine_results)


# A writable mapping keeps a writer handle alive, so the bound path must be refused.
@pytest.mark.skipif(os.name != "nt", reason="Windows share mode is required")
def test_writable_mapping_blocks_bound_measurement(tmp_path: Path) -> None:
    initial = MARKER.ljust(128, b"A")
    path = tmp_path / "changing.bin"
    path.write_bytes(initial)
    with path.open("r+b", buffering=0) as writable:
        mapped = mmap.mmap(writable.fileno(), len(initial), access=mmap.ACCESS_WRITE)
    try:
        with pytest.raises(ContentError, match="IN_USE"):
            BoundReader.measure_path(str(path), max_bytes=128, cancel=NeverCancel())
    finally:
        mapped.close()
