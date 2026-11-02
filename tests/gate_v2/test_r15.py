"""Findings of the independent review R15 that concern Gate v2 (see REVIEWS.md)."""

from __future__ import annotations

import hashlib
import io
import struct
import threading
import time
import zipfile

from sentinel.gate_v2 import archive
from sentinel.gate_v2.contract import ActionCode, ScanRequest, VerdictCode
from sentinel.gate_v2.core import CoreAdapter
from sentinel.gate_v2.coverage import CoverageLedger
from sentinel.gate_v2.events import EventStream
from sentinel.gate_v2.orchestrator import scan, scan_many
from sentinel.gate_v2.policy import RequiredStages, decide


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


def memory(data: bytes, file_id: str = "file") -> ScanRequest:
    return ScanRequest(2, "scan", file_id, None, data, "test", "memory", "evidence-v1",
                       "evidence-v1", time.monotonic_ns() + 5_000_000_000, None, False)


def test_r15_5_requests_are_pulled_as_workers_free_up() -> None:
    # A whole-machine source must not become an unbounded backlog of futures.
    pulled = 0
    release = threading.Event()

    def requests():
        nonlocal pulled
        for i in range(10_000):
            pulled += 1
            yield memory(b"ordinary", f"file-{i}")

    class Blocked(CoreAdapter):
        def scan_bound(self, request, measured, cancel, reader):
            assert release.wait(10)
            return super().scan_bound(request, measured, cancel, reader)

    done: list[object] = []
    thread = threading.Thread(target=lambda: done.append(scan_many(
        requests(), adapters=[Blocked()], gate_generation="r15", auto_quarantine=False, workers=2)), daemon=True)
    thread.start()
    time.sleep(0.3)
    try:
        assert pulled <= 16
    finally:
        release.set()
        thread.join(30)
    assert len(done[0]) == 10_000


def test_r15_6_a_file_that_can_never_be_admitted_does_not_wait_forever() -> None:
    stream = EventStream("scan", terminal_capacity=2)  # one adapter needs three slots
    result: list[object] = []
    thread = threading.Thread(target=lambda: result.extend(scan_many(
        [memory(b"ordinary")], adapters=[CoreAdapter()], gate_generation="r15",
        auto_quarantine=False, emit=stream)), daemon=True)
    thread.start()
    thread.join(3)
    assert not thread.is_alive()
    assert result[0].verdict is VerdictCode.UNKNOWN and result[0].reason_codes == ("ADMISSION_FULL",)


def test_r15_10_a_hit_on_an_empty_file_is_not_lost() -> None:
    digest = hashlib.sha256(b"").hexdigest()
    decision = scan(memory(b""), adapters=[CoreAdapter(known_bad=lambda h: h == digest)],
                    gate_generation="r15", auto_quarantine=False)
    assert decision.verdict is VerdictCode.MALICIOUS


def test_r15_11_no_results_is_not_clean() -> None:
    decision = decide((), memory(b""), "r15", stages=RequiredStages(frozenset()))
    assert decision.verdict is VerdictCode.UNKNOWN and not decision.trusted_clean


def test_r15_12_nothing_to_quarantine_without_a_file() -> None:
    decision = scan(memory(b"ordinary"), adapters=[CoreAdapter(known_bad=lambda _: True)],
                    gate_generation="r15", auto_quarantine=True)
    assert decision.verdict is VerdictCode.MALICIOUS
    assert decision.action_decision.action is ActionCode.NOTIFY


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
