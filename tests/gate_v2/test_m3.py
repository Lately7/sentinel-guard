from __future__ import annotations

import hashlib
import io
import os
import time
import zipfile
from pathlib import Path

import pytest

from conftest import EICAR, MARKER
from sentinel.gate_v2.content import BoundReader, ContentError
from sentinel.gate_v2.contract import (ByteRange, ScanRequest, StageStatus,
                                       Strength, VerdictCode)
from sentinel.gate_v2.core import CoreAdapter, _pe_signals
from sentinel.gate_v2.identity import measure, measure_bytes
from sentinel.gate_v2.orchestrator import scan
from sentinel.gate_v2.rules import JsonRulesAdapter, YaraXAdapter


class Token:
    def cancelled(self) -> bool:
        return False


def request(*, path: Path | None = None, data: bytes | None = None) -> ScanRequest:
    return ScanRequest(2, "m3", "file", str(path) if path else None, data,
                       "test", "single_file", "evidence-v1", "evidence-v1",
                       time.monotonic_ns() + 30_000_000_000, None, False)


def bound(data: bytes) -> tuple[ScanRequest, BoundReader]:
    measured = measure_bytes(data).identity
    assert measured
    return request(data=data), BoundReader.from_bytes(data, measured)


def test_core_eicar_and_known_bad() -> None:
    for body, lookup, code in ((EICAR, None, "EICAR"),
                               (b"known-bad-marker", lambda _: True, "KNOWN_BAD_HASH")):
        req, reader = bound(body)
        result = CoreAdapter(lookup).scan_bound(req, reader.identity, Token(), reader)
        assert result.verdict is VerdictCode.MALICIOUS
        assert result.evidence[0].strength is Strength.CONCLUSIVE
        assert result.evidence[0].detail_code == code
        assert result.evidence[0].is_test_file is (code == "EICAR")
        assert result.coverage.inspected == (ByteRange(0, len(body)),)


def test_name_and_pe_stay_weak(tmp_path: Path) -> None:
    path = tmp_path / "photo.pdf.exe"
    path.write_bytes(b"harmless")
    decision = scan(request(path=path), adapters=[CoreAdapter()], gate_generation="m3",
                    auto_quarantine=False)
    assert decision.verdict is VerdictCode.SUSPICIOUS
    assert all(e.strength is not Strength.CONCLUSIVE for e in decision.engine_results[0].evidence)
    pe = bytearray(8192)
    pe[:2] = b"MZ"
    pe[0x3c:0x40] = (0x80).to_bytes(4, "little")
    pe[0x80:0x84] = b"PE\0\0"
    pe[0x86:0x88] = (1).to_bytes(2, "little")
    pe[0x94:0x96] = (224).to_bytes(2, "little")
    pe[0x98:0x9a] = (0x10b).to_bytes(2, "little")
    section = 0x80 + 24 + 224
    pe[section + 16:section + 20] = (4096).to_bytes(4, "little")
    pe[section + 20:section + 24] = (4096).to_bytes(4, "little")
    pe[section + 36:section + 40] = (0x20000000).to_bytes(4, "little")
    pe[4096:] = bytes(range(256)) * 16
    assert "PE_PACKED_SECTION" in _pe_signals(bytes(pe))
    assert "PE_MALFORMED" in _pe_signals(b"MZ" + b"\0" * 30)
    req, reader = bound(bytes(pe))
    result = CoreAdapter().scan_bound(req, reader.identity, Token(), reader)
    assert all(e.strength is not Strength.CONCLUSIVE for e in result.evidence)


def _zip(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, body in entries:
            archive.writestr(name, body)
    return output.getvalue()


def _zip_result(body: bytes):
    req, reader = bound(body)
    return CoreAdapter().scan_bound(req, reader.identity, Token(), reader)


def test_zip_member_states(monkeypatch: pytest.MonkeyPatch) -> None:
    normal = _zip([("entry", b"hello")])
    encrypted = bytearray(normal)
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        at = encrypted.find(sig)
        flag = at + (6 if sig.endswith(b"\x04") else 8)
        encrypted[flag:flag + 2] = (1).to_bytes(2, "little")
    assert "ENCRYPTED" in _zip_result(bytes(encrypted)).coverage.object_reasons
    method = bytearray(normal)
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        at = method.find(sig)
        slot = at + (8 if sig.endswith(b"\x04") else 10)
        method[slot:slot + 2] = (99).to_bytes(2, "little")
    assert "UNSUPPORTED_METHOD" in _zip_result(bytes(method)).coverage.object_reasons
    malformed = _zip_result(normal[:-10])
    assert malformed.status is StageStatus.PARTIAL
    many = _zip([(f"f{i}", b"") for i in range(2001)])
    assert "MEMBER_LIMIT" in _zip_result(many).coverage.object_reasons
    nested = b"plain"
    for _ in range(5):
        nested = _zip([("child.zip", nested)])
    assert "DEPTH_LIMIT" in _zip_result(nested).coverage.object_reasons
    oversize = bytearray(normal)
    at = oversize.find(b"PK\x01\x02")
    oversize[at + 24:at + 28] = (65 * 1024 * 1024).to_bytes(4, "little")
    assert "MEMBER_SIZE_LIMIT" in _zip_result(bytes(oversize)).coverage.object_reasons
    original = zipfile.ZipFile
    def broken(*args, **kwargs):
        raise zipfile.BadZipFile("synthetic")
    monkeypatch.setattr(zipfile, "ZipFile", broken)
    assert _zip_result(normal).status is StageStatus.PARTIAL
    monkeypatch.setattr(zipfile, "ZipFile", original)


def test_json_manifest_policy_and_digest(marker_rule: Path) -> None:
    user = JsonRulesAdapter.from_directories(marker_rule.parent)
    bad = JsonRulesAdapter((("bad", b"{", False), ("good", marker_rule.read_bytes(), True)))
    assert bad.readiness() == "RULES_DEGRADED"
    assert len(bad.rules) == 1 and not bad.manifest[0].accepted
    req, reader = bound(MARKER)
    hit = user.scan_bound(req, reader.identity, Token(), reader)
    assert hit.evidence[0].strength is Strength.CONCLUSIVE
    bundled = JsonRulesAdapter((("bundle", marker_rule.read_bytes(), False),))
    req, reader = bound(MARKER)
    assert bundled.scan_bound(req, reader.identity, Token(), reader).evidence[0].strength is Strength.SUPPORTING
    changed = marker_rule.read_bytes().replace(b"test marker", b"tast marker")
    assert JsonRulesAdapter((("bundle", changed, False),)).ruleset_digest != bundled.ruleset_digest


def test_bound_reader_limits_and_change(tmp_path: Path) -> None:
    path = tmp_path / "one"
    path.write_bytes(b"abcdef")
    measured = measure(str(path)).identity
    assert measured
    path.write_bytes(b"other")
    with path.open("rb") as stream:
        with pytest.raises(ContentError, match="CHANGED"):
            BoundReader.from_stream(stream, measured)
    req, reader = bound(b"a" * (1024 * 1024 + 1))
    reader.resident_limit = 1024 * 1024
    with pytest.raises(ContentError, match="RESIDENT_LIMIT"):
        reader.read(0, reader.resident_limit + 1, Token())
    class Cancels:
        calls = 0
        def cancelled(self) -> bool:
            self.calls += 1
            return self.calls > 2
    with pytest.raises(ContentError, match="CANCELLED"):
        reader.read(0, 1024 * 1024 + 1, Cancels())


def test_end_to_end(marker_rule: Path, tmp_path: Path) -> None:
    rules = JsonRulesAdapter.from_directories(marker_rule.parent)
    path = tmp_path / "positive"
    path.write_bytes(MARKER)
    hit = scan(request(path=path), adapters=[CoreAdapter(), rules], gate_generation="m3",
               auto_quarantine=False, skip_after_conclusive=False)
    assert hit.verdict is VerdictCode.MALICIOUS
    clean_path = tmp_path / "clean"
    clean_path.write_bytes(b"ordinary harmless bytes")
    clean = scan(request(path=clean_path), adapters=[CoreAdapter(), rules],
                 gate_generation="m3", auto_quarantine=False)
    assert clean.verdict is VerdictCode.CLEAN and clean.trusted_clean


def test_yara_namespaces_and_degraded() -> None:
    pytest.importorskip("yara_x", reason="yara_x is not installed")
    sources = (("a", "a.yar", 'rule Same { condition: true }'),
               ("b", "b.yar", 'rule Same { condition: true }'),
               ("bad", "bad.yar", 'rule Broken { condition: }'))
    adapter = YaraXAdapter(sources)
    assert adapter.readiness() == "RULES_DEGRADED"
    assert any(not item.accepted for item in adapter.manifest)
    req, reader = bound(b"harmless")
    result = adapter.scan_bound(req, reader.identity, Token(), reader)
    assert {(e.source_id, e.signature_id) for e in result.evidence} == {("a", "Same"), ("b", "Same")}


def test_yara_one_scanner_per_thread() -> None:
    pytest.importorskip("yara_x", reason="yara_x is not installed")
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier, get_ident
    adapter = YaraXAdapter((("a", "a.yar", 'rule Ready { condition: true }'),))
    barrier = Barrier(2)
    def worker():
        scanner = adapter._scanner()
        barrier.wait()
        return get_ident(), scanner
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(worker)
        second = pool.submit(worker)
        a, b = first.result(), second.result()
    assert a[0] != b[0] and a[1] is not b[1]
