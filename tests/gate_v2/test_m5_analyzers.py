"""Synthetic structural and origin observations never become malware evidence."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from sentinel.gate_v2.analyzers.lnk import LnkAdapter, parse as parse_lnk
from sentinel.gate_v2.analyzers.motw import MotwAdapter, parse as parse_motw
from sentinel.gate_v2.analyzers.signer import SignerAdapter, certificate_present
from sentinel.gate_v2.content import BoundReader
from sentinel.gate_v2.contract import Category, ScanRequest, StageStatus, Strength, VerdictCode
from sentinel.gate_v2.core import CoreAdapter
from sentinel.gate_v2.identity import measure_bytes
from sentinel.gate_v2.orchestrator import scan


class Token:
    def cancelled(self) -> bool:
        return False


def request(data: bytes | None = None, path: Path | None = None) -> ScanRequest:
    return ScanRequest(2, "m5-context", "file", str(path) if path else None, data,
                       "test", "single_file", "evidence-v1", "evidence-v1",
                       time.monotonic_ns() + 5_000_000_000, None, False)


def direct(adapter, body: bytes):
    measured = measure_bytes(body).identity
    assert measured is not None
    reader = BoundReader.from_bytes(body, measured)
    return adapter.scan_bound(request(data=body), measured, Token(), reader)


def lnk(target: str = "note.txt", arguments: str = "") -> bytes:
    body = bytearray(76)
    body[:4] = (76).to_bytes(4, "little")
    body[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    body[20:24] = (8 | 32 | 0x80).to_bytes(4, "little")
    for value in (target, arguments):
        body += len(value).to_bytes(2, "little") + value.encode("utf-16le")
    return bytes(body)


def pe(cert: bool) -> bytes:
    body = bytearray(512)
    body[:2] = b"MZ"
    body[0x3c:0x40] = (0x80).to_bytes(4, "little")
    body[0x80:0x84] = b"PE\0\0"
    body[0x94:0x96] = (224).to_bytes(2, "little")
    body[0x98:0x9a] = (0x10b).to_bytes(2, "little")
    if cert:
        entry = 0x98 + 96 + 32
        body[entry:entry + 4] = (480).to_bytes(4, "little")
        body[entry + 4:entry + 8] = (16).to_bytes(4, "little")
    return bytes(body)


def assert_context(result) -> None:
    assert result.verdict is not VerdictCode.MALICIOUS
    assert all(not (e.category is Category.MALWARE and e.strength is Strength.CONCLUSIVE)
               for e in result.evidence)


def test_lnk_valid_script_host_and_malformed() -> None:
    ordinary = direct(LnkAdapter(), lnk())
    assert ordinary.status is StageStatus.COMPLETED
    assert not ordinary.evidence
    scripted = direct(LnkAdapter(), lnk(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-NoProfile"))
    assert scripted.evidence[0].detail_code == "LNK_TARGETS_SCRIPT_HOST"
    assert scripted.evidence[0].strength is Strength.SUPPORTING
    assert_context(scripted)
    assert parse_lnk(lnk()[:20])[1] == "not_lnk"
    assert direct(LnkAdapter(), lnk()[:20]).status is StageStatus.COMPLETED
    hostile = bytearray(lnk())
    hostile[76:78] = (65535).to_bytes(2, "little")
    assert direct(LnkAdapter(), bytes(hostile)).status is StageStatus.PARTIAL
    decision = scan(request(data=lnk()), adapters=[LnkAdapter()],
                    gate_generation="m5", auto_quarantine=False)
    # A context parser is no malware scan: required alone, it clears nothing.
    assert decision.verdict is VerdictCode.UNKNOWN
    assert not decision.trusted_clean


def test_pe_certificate_presence_is_not_trust() -> None:
    assert certificate_present(pe(True), 512) == (True, "complete")
    assert certificate_present(pe(False), 512) == (False, "complete")
    present = direct(SignerAdapter(trust=lambda *_: pytest.fail("no handle")), pe(True))
    absent = direct(SignerAdapter(), pe(False))
    assert {e.detail_code for e in present.evidence} == {"CERTIFICATE_PRESENT", "TRUST_UNAVAILABLE"}
    assert {e.detail_code for e in absent.evidence} == {"CERTIFICATE_ABSENT", "TRUST_UNAVAILABLE"}
    assert_context(present)
    assert direct(SignerAdapter(), b"MZ" + b"\0" * 10).status is StageStatus.PARTIAL


@pytest.mark.parametrize("state", ["valid", "unsigned", "invalid", "revoked", "unavailable"])
def test_injected_trust_states(tmp_path: Path, state: str) -> None:
    path = tmp_path / "synthetic.exe"
    path.write_bytes(pe(True))
    adapter = SignerAdapter(trust=lambda *_: state)
    decision = scan(request(path=path), adapters=[adapter], gate_generation="m5",
                    auto_quarantine=False)
    observed = decision.engine_results[0]
    assert "TRUST_" + (state.upper() if __import__("os").name == "nt" else "UNAVAILABLE") in {e.detail_code for e in observed.evidence}
    assert_context(observed)
    assert decision.verdict is not VerdictCode.MALICIOUS


def test_valid_signer_cannot_lower_conclusive_hash(tmp_path: Path) -> None:
    path = tmp_path / "synthetic.exe"
    path.write_bytes(pe(True))
    decision = scan(request(path=path),
                    adapters=[SignerAdapter(trust=lambda *_: "valid"),
                              CoreAdapter(known_bad=lambda _: True)],
                    gate_generation="m5", auto_quarantine=False)
    assert decision.verdict is VerdictCode.MALICIOUS
    assert ("TRUST_VALID" if __import__("os").name == "nt" else "TRUST_UNAVAILABLE") in {e.detail_code for e in decision.engine_results[0].evidence}


@pytest.mark.parametrize("zone", range(5))
def test_motw_zones_are_origin_context(tmp_path: Path, zone: int) -> None:
    path = tmp_path / "ordinary.txt"
    path.write_bytes(b"ordinary")
    text = (f"[ZoneTransfer]\nZoneId={zone}\n"
            "HostUrl=https://example.test/a\nReferrerUrl=https://example.test/b\n")
    adapter = MotwAdapter(reader=lambda _: text)
    decision = scan(request(path=path), adapters=[adapter], gate_generation="m5",
                    auto_quarantine=False)
    observed = decision.engine_results[0]
    assert {e.detail_code for e in observed.evidence} == {
        f"ZONE_{zone}", "HOST_URL_PRESENT", "REFERRER_URL_PRESENT"}
    assert all(e.category is Category.ORIGIN and e.strength is Strength.CONTEXT
               for e in observed.evidence)
    assert_context(observed)
    assert decision.verdict is not VerdictCode.MALICIOUS


def test_motw_malformed_and_bounded(tmp_path: Path) -> None:
    path = tmp_path / "ordinary.txt"
    path.write_bytes(b"ordinary")
    for text in ("[ZoneTransfer]\nZoneId=oops", "[ZoneTransfer]\nHostUrl=" + "a" * 2049,
                 "[ZoneTransfer]\nZoneId=3\nmissing equals"):
        adapter = MotwAdapter(reader=lambda _, value=text: value)
        observed = scan(request(path=path), adapters=[adapter], gate_generation="m5",
                        auto_quarantine=False).engine_results[0]
        assert observed.status is StageStatus.PARTIAL
        assert_context(observed)
    assert parse_motw("x" * 8193).malformed
