from __future__ import annotations

import io
import json
import os
import time
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import EICAR, MARKER
from sentinel.gate_v2.content import BoundReader, ContentError
from sentinel.gate_v2 import archive
from sentinel.gate_v2.coverage import CoverageLedger
from sentinel.gate_v2.contract import (ByteRange, ScanRequest, StageStatus,
                                       Strength, VerdictCode)
from sentinel.gate_v2.core import CoreAdapter, _pe_signals
from sentinel.gate_v2.identity import measure, measure_bytes
from sentinel.gate_v2.orchestrator import scan
from sentinel.gate_v2.rules import JsonRulesAdapter, YaraXAdapter

pytestmark = pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning")

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
    assert "MAX_CHILDREN" in _zip_result(many).coverage.object_reasons
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
    reader.resident_limit += 1
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


def test_eicar_member_is_conclusive_in_memory() -> None:
    hit = scan(request(data=_zip([("eicar.txt", EICAR)])), adapters=[CoreAdapter()],
               gate_generation="m3", auto_quarantine=False)
    assert hit.verdict is VerdictCode.MALICIOUS
    evidence = hit.engine_results[0].evidence
    assert any(e.detail_code == "EICAR" and e.scope == "member" and e.is_test_file for e in evidence)


def test_json_member_and_nested_member(marker_rule: Path, tmp_path: Path) -> None:
    rules = JsonRulesAdapter.from_directories(marker_rule.parent)
    for payload, expected in ((_zip([("marker.txt", MARKER)]), "marker.txt"),
                              (_zip([("inside.zip", _zip([("marker.txt", MARKER)]))]),
                               "inside.zip/marker.txt")):
        path = tmp_path / "sample.zip"
        path.write_bytes(payload)
        hit = scan(request(path=path), adapters=[CoreAdapter(), rules],
                   gate_generation="m3", auto_quarantine=False)
        assert hit.verdict is VerdictCode.MALICIOUS
        assert any(e.scope == "member" and e.member_path == expected and
                   e.strength is Strength.CONCLUSIVE for e in hit.engine_results[1].evidence)


def test_archive_depth_debt_all_engines(marker_rule: Path) -> None:
    payload = MARKER
    for _ in range(5):
        payload = _zip([("inside.zip", payload)])
    adapters = [CoreAdapter(), JsonRulesAdapter.from_directories(marker_rule.parent)]
    hit = scan(request(data=payload), adapters=adapters,
               gate_generation="m3", auto_quarantine=False)
    assert hit.verdict is not VerdictCode.CLEAN and not hit.trusted_clean
    assert all("DEPTH_LIMIT" in result.coverage.object_reasons for result in hit.engine_results)


@pytest.mark.skipif(os.name != "nt", reason="Windows share mode is required")
def test_bound_reader_denies_writers(tmp_path: Path) -> None:
    import ctypes

    path = tmp_path / "shared"
    path.write_bytes(b"safe")
    reader = BoundReader.measure_path(str(path), max_bytes=100, cancel=Token())
    kernel = ctypes.windll.kernel32
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                   ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    try:
        writer = kernel.CreateFileW(str(path), 0x40000000, 0x7, None, 3, 0x80, None)
        assert writer == ctypes.c_void_p(-1).value
    finally:
        reader.close()
    writer = kernel.CreateFileW(str(path), 0x40000000, 0x7, None, 3, 0x80, None)
    assert writer != ctypes.c_void_p(-1).value
    try:
        with pytest.raises(ContentError, match="IN_USE"):
            BoundReader.measure_path(str(path), max_bytes=100, cancel=Token())
    finally:
        kernel.CloseHandle(ctypes.c_void_p(writer))


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
        identifier = get_ident()
        result = scanner.scan(b"safe")
        del scanner
        return identifier, len(result.matching_rules)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(worker)
        second = pool.submit(worker)
        a, b = first.result(), second.result()
    assert a[0] != b[0] and a[1] == b[1] == 1


def test_yara_provenance_and_member() -> None:
    pytest.importorskip("yara_x", reason="yara_x is not installed")
    adapter = YaraXAdapter((("sample", "sample.yar",
                             'rule Marker : local { strings: $a = "MAGICMARK" condition: $a }'),),
                           max_matches_per_pattern=2)
    req, reader = bound(b"xMAGICMARKyMAGICMARKzMAGICMARK")
    result = adapter.scan_bound(req, reader.identity, Token(), reader)
    assert result.evidence[0].raw_name == "sample.Marker"
    assert result.evidence[0].ranges == (ByteRange(1, 10), ByteRange(11, 20))
    req, reader = bound(_zip([("inner.txt", b"MAGICMARK")]))
    result = adapter.scan_bound(req, reader.identity, Token(), reader)
    assert any(e.scope == "member" and e.member_path == "inner.txt" for e in result.evidence)


def test_late_eicar_survives_evidence_cap() -> None:
    payload = _zip([(f"invoice{i}.pdf.exe", b"harmless") for i in range(80)] +
                   [("eicar.txt", EICAR)])
    hit = scan(request(data=payload), adapters=[CoreAdapter()],
               gate_generation="m3", auto_quarantine=False)
    result = hit.engine_results[0]
    assert hit.verdict is VerdictCode.MALICIOUS
    assert any(e.detail_code == "EICAR" and e.is_test_file for e in result.evidence)
    assert any(e.detail_code == "DOUBLE_EXTENSION_COUNT_80" for e in result.evidence)
    assert "EVIDENCE_CAP" in result.coverage.limits_hit


def test_late_user_rule_survives_evidence_cap(marker_rule: Path) -> None:
    weak = json.dumps({"rules": [{"id": "weak", "severity": "medium",
                                    "text": ["harmless"]}]}).encode()
    rule = JsonRulesAdapter((("bundle", weak, False), ("user", marker_rule.read_bytes(), True)))
    payload = _zip([(f"invoice{i}.pdf.exe", b"harmless") for i in range(80)] +
                   [("last.txt", MARKER)])
    hit = scan(request(data=payload), adapters=[CoreAdapter(), rule],
               gate_generation="m3", auto_quarantine=False, skip_after_conclusive=False)
    assert hit.verdict is VerdictCode.MALICIOUS
    assert any(e.member_path == "last.txt" and e.strength is Strength.CONCLUSIVE
               for e in hit.engine_results[1].evidence)
    assert "EVIDENCE_CAP" in hit.engine_results[1].coverage.limits_hit


def test_archive_deadline_omits_remaining_members() -> None:
    payload = _zip([(f"item{i}", b"safe") for i in range(3)])
    ticks = iter((0, 2))
    ledger = CoverageLedger(len(payload))
    seen: list[str] = []
    stopped = archive.walk(payload, ledger, Token(), lambda name, _: seen.append(name),
                           1, clock=lambda: next(ticks))
    assert stopped == "DEADLINE"
    assert seen == ["item0"]
    assert ledger.objects_inspected == 1 and ledger.objects_omitted == 2
    assert ledger.finish().mode == "runtime_partial"
    assert "DEADLINE" in ledger.finish().object_reasons


@pytest.mark.parametrize("adapter_kind", ["core", "json", "yara"])
def test_member_deadline_returns_timeout(adapter_kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    if adapter_kind == "yara":
        pytest.importorskip("yara_x", reason="yara_x is not installed")
    adapter = (CoreAdapter() if adapter_kind == "core" else
               JsonRulesAdapter((("user", json.dumps({"rules": [{"id": "r", "severity": "critical",
                    "text": ["UNMATCHABLE"]}]}).encode(), True),)) if adapter_kind == "json" else
               YaraXAdapter((("safe", "safe.yar", "rule Safe { condition: false }"),)))
    original = archive.walk
    def controlled(*args, **kwargs):
        ticks = iter((0, 2))
        return original(*args, **kwargs, clock=lambda: next(ticks))
    monkeypatch.setattr(archive, "walk", controlled)
    req, reader = bound(_zip([("one", b"safe"), ("two", b"safe")]))
    req = replace(req, deadline_monotonic_ns=1)
    result = adapter.scan_bound(req, reader.identity, Token(), reader)
    assert result.status is StageStatus.TIMEOUT
    assert result.verdict is not VerdictCode.CLEAN
    assert result.coverage.objects_omitted == 1
    assert "DEADLINE" in result.coverage.limits_hit


def test_yara_timeout_is_typed(monkeypatch: pytest.MonkeyPatch) -> None:
    yara_x = pytest.importorskip("yara_x", reason="yara_x is not installed")
    adapter = YaraXAdapter((("safe", "safe.yar", "rule Safe { condition: false }"),), timeout=1)
    class SlowScanner:
        def scan(self, _: bytes):
            raise yara_x.TimeoutError("synthetic timeout")
    monkeypatch.setattr(adapter, "_scanner", lambda: SlowScanner())
    req, reader = bound(b"harmless")
    result = adapter.scan_bound(req, reader.identity, Token(), reader)
    assert result.status is StageStatus.TIMEOUT
    assert result.verdict is VerdictCode.UNKNOWN
    assert result.error and result.error.code == "YARA_TIMEOUT"


def test_yara_warning_and_rejected_source_manifest() -> None:
    pytest.importorskip("yara_x", reason="yara_x is not installed")
    adapter = YaraXAdapter((("warn", "warn.yar", "rule Warn { strings: $a = /./ condition: $a }"),
                            ("bad", "bad.yar", "rule Broken { condition: }"),
                            ("good", "good.yar", "rule Good { condition: true }")))
    assert adapter.readiness() == "RULES_DEGRADED"
    assert any(item.name == "bad.yar" and not item.accepted and item.reason == "COMPILE_ERROR"
               for item in adapter.manifest)
    assert any(item.name == "good.yar" and item.accepted for item in adapter.manifest)
    assert any("slow_pattern" in detail for item in adapter.manifest for detail in item.details)
    req, reader = bound(b"safe")
    result = adapter.scan_bound(req, reader.identity, Token(), reader)
    assert result.status is StageStatus.PARTIAL
    assert "RULES_DEGRADED" in result.coverage.limits_hit
    assert any(e.signature_id == "Good" for e in result.evidence)


def test_same_json_rule_user_and_bundle_strength(marker_rule: Path) -> None:
    raw = marker_rule.read_bytes()
    for user, expected in ((False, Strength.SUPPORTING), (True, Strength.CONCLUSIVE)):
        req, reader = bound(MARKER)
        adapter = JsonRulesAdapter((("pack", raw, user),))
        result = adapter.scan_bound(req, reader.identity, Token(), reader)
        assert result.evidence[0].strength is expected


def test_end_to_end_clean_with_all_local_engines(marker_rule: Path) -> None:
    pytest.importorskip("yara_x", reason="yara_x is not installed")
    adapters = [CoreAdapter(), JsonRulesAdapter((("user", marker_rule.read_bytes(), True),)),
                YaraXAdapter((("safe", "safe.yar", "rule Safe { condition: false }"),))]
    decision = scan(request(data=b"ordinary harmless bytes"), adapters=adapters,
                    gate_generation="m3", auto_quarantine=False)
    # M1 trusts a clean result only when every required stage completed with verified full coverage.
    assert decision.verdict is VerdictCode.CLEAN and decision.trusted_clean
    assert all(item.status is StageStatus.COMPLETED for item in decision.engine_results)
