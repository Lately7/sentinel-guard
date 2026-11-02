"""Synthetic container differentials; no sample bytes are written to disk."""

from __future__ import annotations

import io
import struct
import time
import zipfile

import pytest

from sentinel.gate_v2 import archive
from sentinel.gate_v2.contract import ScanRequest, VerdictCode
from sentinel.gate_v2.core import CoreAdapter
from sentinel.gate_v2.coverage import CoverageLedger
from sentinel.gate_v2.orchestrator import scan


class NeverCancel:
    def cancelled(self) -> bool:
        return False


def zip_bytes(entries: list[tuple[str, bytes]], compression: int = zipfile.ZIP_STORED) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=compression) as bundle:
        for name, body in entries:
            bundle.writestr(name, body)
    return out.getvalue()


def walk_bytes(data: bytes) -> tuple[CoverageLedger, list[tuple[str, bytes]]]:
    ledger = CoverageLedger(len(data))
    inspected: list[tuple[str, bytes]] = []
    archive.walk(data, ledger, NeverCancel(), lambda name, body: inspected.append((name, body)),
                 time.monotonic_ns() + 5_000_000_000)
    return ledger, inspected


def core_decision(data: bytes):
    request = ScanRequest(2, "archive-edge", "file", None, data, "test", "memory",
                          "evidence-v1", "evidence-v1", time.monotonic_ns() + 5_000_000_000,
                          None, False)
    return scan(request, adapters=[CoreAdapter()], gate_generation="edge", auto_quarantine=False)


def test_prepended_zip_members_are_inspected() -> None:
    # R11 invariant 7: a valid ZIP with a prefix still has child objects to account for.
    data = b"harmless preamble" + zip_bytes([("child.txt", b"harmless child")])
    assert zipfile.is_zipfile(io.BytesIO(data))
    decision = core_decision(data)
    assert decision.engine_results[0].coverage.objects_inspected == 1
    disguised = b"harmless preamble" + zip_bytes([("child.pdf.exe", b"harmless child")])
    assert core_decision(disguised).verdict is VerdictCode.SUSPICIOUS


def test_embedded_zip_at_nonzero_offset_is_not_certified_clean() -> None:
    # R11 invariant 7: a stored member that is itself a prefixed ZIP has nested coverage debt.
    inner = b"prefix" + zip_bytes([("deep.txt", b"harmless deep child")])
    ledger, seen = walk_bytes(zip_bytes([("inner.bin", inner)]))
    assert zipfile.is_zipfile(io.BytesIO(inner))
    assert any(name == "inner.bin" for name, _ in seen)
    assert ledger.finish().mode != "full" or any(name.endswith("deep.txt") for name, _ in seen)


def test_duplicate_member_names_are_both_inspected() -> None:
    # R11 invariant 7: identical names do not collapse two physical members.
    with pytest.warns(UserWarning, match="Duplicate name"):
        data = zip_bytes([("same.txt", b"first harmless body"), ("same.txt", b"second harmless body")])
    ledger, seen = walk_bytes(data)
    assert [body for _, body in seen] == [b"first harmless body", b"second harmless body"]
    assert ledger.objects_inspected == 2


def test_data_descriptor_size_disagreement_is_opaque() -> None:
    # R11 invariant 7: contradictory descriptor metadata cannot prove full coverage.
    class Unseekable(io.RawIOBase):
        def __init__(self) -> None:
            self.data = bytearray()

        def writable(self) -> bool:
            return True

        def write(self, value: bytes) -> int:
            self.data.extend(value)
            return len(value)

    sink = Unseekable()
    with zipfile.ZipFile(sink, "w", zipfile.ZIP_STORED) as bundle:
        bundle.writestr("child.txt", b"harmless child")
    data = bytearray(sink.data)
    descriptor = data.index(b"PK\x07\x08")
    struct.pack_into("<I", data, descriptor + 8, 1)  # compressed size
    ledger, _ = walk_bytes(bytes(data))
    assert ledger.objects_inspected == 0
    assert ledger.objects_opaque + ledger.objects_omitted >= 1


def test_overlapping_local_member_offsets_are_not_full_coverage() -> None:
    # R11 invariant 7: two directory entries pointing at one body are ambiguous.
    data = bytearray(zip_bytes([("one.txt", b"harmless one"), ("two.txt", b"harmless two")]))
    first = data.index(b"PK\x01\x02")
    second = data.index(b"PK\x01\x02", first + 4)
    first_offset = struct.unpack_from("<I", data, first + 42)[0]
    struct.pack_into("<I", data, second + 42, first_offset)
    ledger, _ = walk_bytes(bytes(data))
    assert ledger.finish().mode != "full"


def test_unicode_extra_name_conflict_is_not_full_coverage() -> None:
    # R11 invariant 7: a Unicode path extra field must not rename the inspected object silently.
    data = bytearray(zip_bytes([("one.txt", b"harmless child")]))
    central = data.index(b"PK\x01\x02")
    name_len = struct.unpack_from("<H", data, central + 28)[0]
    extra_at = central + 46 + name_len
    import zlib
    extra_body = b"\x01" + struct.pack("<I", zlib.crc32(b"one.txt")) + b"other.txt"
    extra = struct.pack("<HH", 0x7075, len(extra_body)) + extra_body
    data[extra_at:extra_at] = extra
    struct.pack_into("<H", data, central + 30, len(extra))
    eocd = data.index(b"PK\x05\x06")
    central_size = struct.unpack_from("<I", data, eocd + 12)[0]
    struct.pack_into("<I", data, eocd + 12, central_size + len(extra))
    ledger, _ = walk_bytes(bytes(data))
    assert ledger.finish().mode != "full"
