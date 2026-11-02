"""Lexical Windows path boundaries without opening device names."""

from __future__ import annotations

import os
import time
import hashlib
from pathlib import Path

import pytest

from sentinel.gate_v2.contract import ContractError, ScanRequest, VerdictCode
from sentinel.gate_v2.core import CoreAdapter
from sentinel.gate_v2.orchestrator import scan


def request(path: str) -> ScanRequest:
    return ScanRequest(2, "path-edge", "file", path, None, "test", "single_file",
                       "evidence-v1", "evidence-v1", time.monotonic_ns() + 5_000_000_000,
                       None, False)


@pytest.mark.skipif(os.name != "nt", reason="NTFS component limits require Windows")
def test_component_over_255_utf16_units_is_typed_unknown(tmp_path: Path) -> None:
    # R11 invariant 7: an invalid NTFS component is reported without an exception.
    path = str(tmp_path / ("a" * 256 + ".txt"))
    decision = scan(request(path), adapters=[CoreAdapter()], gate_generation="edge",
                    auto_quarantine=False)
    assert decision.verdict is VerdictCode.UNKNOWN
    assert not decision.trusted_clean


@pytest.mark.skipif(os.name != "nt", reason="Windows MAX_PATH behavior requires Windows")
def test_nonexistent_path_over_260_is_typed_unknown(tmp_path: Path) -> None:
    # R11 invariant 7: an extended-length path error is a typed scan outcome.
    path = str(tmp_path / ("a" * 200) / ("b" * 80) / "ordinary.txt")
    assert len(path) > 260
    decision = scan(request(path), adapters=[CoreAdapter()], gate_generation="edge",
                    auto_quarantine=False)
    assert decision.verdict is VerdictCode.UNKNOWN


def test_path_over_32767_is_rejected_by_contract() -> None:
    # R11 invariant 8: the input contract bounds extreme paths before any I/O.
    with pytest.raises(ContractError, match="INVALID_PATH"):
        request("C:/" + "a" * 32768)


@pytest.mark.skipif(os.name != "nt", reason="Windows UTF-16 path conversion requires Windows")
def test_lone_surrogate_path_is_typed_unknown(tmp_path: Path) -> None:
    # R11 invariant 7: malformed UTF-16 text must not escape the scan boundary.
    path = str(tmp_path / "bad-\ud800.txt")
    decision = scan(request(path), adapters=[CoreAdapter()], gate_generation="edge",
                    auto_quarantine=False)
    assert decision.verdict is VerdictCode.UNKNOWN


@pytest.mark.skipif(os.name != "nt", reason="Win32 trailing-space aliasing requires Windows")
@pytest.mark.parametrize("suffix", [".", " "])
def test_trailing_dot_or_space_alias_is_measured_by_handle(tmp_path: Path, suffix: str) -> None:
    # R11 invariant 2: a Win32-normalized alias must bind to the opened generation.
    original = tmp_path / "ordinary.txt"
    original.write_bytes(b"harmless synthetic bytes")
    alias = str(original) + suffix
    try:
        os.stat(alias)
    except OSError as exc:
        pytest.skip(f"Win32 trailing-name alias unavailable: {exc}")
    decision = scan(request(alias), adapters=[CoreAdapter()], gate_generation="edge",
                    auto_quarantine=False)
    assert decision.identity is not None
    assert decision.identity.sha256 == hashlib.sha256(b"harmless synthetic bytes").hexdigest()
