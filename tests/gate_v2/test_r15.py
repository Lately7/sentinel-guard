"""Findings of the independent review R15 that concern Gate v2 (see REVIEWS.md)."""

from __future__ import annotations

import io
import struct
import time
import zipfile

from sentinel.gate_v2 import archive
from sentinel.gate_v2.contract import ScanRequest, VerdictCode
from sentinel.gate_v2.core import CoreAdapter
from sentinel.gate_v2.coverage import CoverageLedger
from sentinel.gate_v2.orchestrator import scan


class Token:
    def cancelled(self) -> bool:
        return False


class Unseekable(io.RawIOBase):
    """zipfile sets the data-descriptor flag when it cannot seek back."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, value) -> int:
        self.data.extend(value)
        return len(value)


TEXT = b"harmless synthetic text " * 8


def stored() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as bundle:
        bundle.writestr("note.txt", TEXT)
    return buffer.getvalue()


def walk(data: bytes) -> tuple[CoverageLedger, list[str]]:
    ledger = CoverageLedger(len(data))
    seen: list[str] = []
    archive.walk(data, ledger, Token(), lambda path, _body: seen.append(path),
                 time.monotonic_ns() + 5_000_000_000)
    return ledger, seen


def test_r15_3_method_disagreement_is_opaque_not_inspected() -> None:
    # Extractors differ on which header wins, so what zipfile read may not be
    # what another program unpacks.
    data = bytearray(stored())
    struct.pack_into("<H", data, 8, zipfile.ZIP_DEFLATED)
    ledger, seen = walk(bytes(data))
    assert not seen
    assert (ledger.objects_opaque, ledger.object_reasons) == (1, ["HEADER_MISMATCH"])
    request = ScanRequest(2, "scan", "file", None, bytes(data), "test", "memory", "evidence-v1",
                          "evidence-v1", time.monotonic_ns() + 5_000_000_000, None, False)
    decision = scan(request, adapters=[CoreAdapter()], gate_generation="r15", auto_quarantine=False)
    assert decision.verdict is VerdictCode.UNKNOWN and not decision.trusted_clean


def test_r15_3_encryption_and_size_disagreement_is_opaque() -> None:
    encrypted = bytearray(stored())
    struct.pack_into("<H", encrypted, 6, 1)
    resized = bytearray(stored())
    struct.pack_into("<I", resized, 22, len(TEXT) + 1)
    for data in (encrypted, resized):
        ledger, seen = walk(bytes(data))
        assert not seen and ledger.object_reasons == ["HEADER_MISMATCH"]


def test_r15_3_ordinary_archives_stay_inspected() -> None:
    deflated = io.BytesIO()
    with zipfile.ZipFile(deflated, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("note.txt", TEXT)
    stream = Unseekable()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("note.txt", TEXT)
    assert bytes(stream.data)[6] & 8, "the data-descriptor flag must be set for this case"
    for data in (stored(), deflated.getvalue(), bytes(stream.data)):
        ledger, seen = walk(data)
        assert seen == ["note.txt"] and ledger.objects_opaque == 0
