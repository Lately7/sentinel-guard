"""Cloud placeholder and download mark regressions."""

from __future__ import annotations

import builtins
import hashlib
import io
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel import quarantine
from sentinel.gate_v2 import identity, scope, winfile
from sentinel.gate_v2.contract import FileIdentity


RECALL_FLAGS = (0x400000, 0x40000, 0x1000)
BODY = b"harmless restore bytes"


def test_zone_read_distinguishes_missing_failed_and_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()))
    assert quarantine._zone_identifier("C:/file.bin") == (None, False)
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError()))
    assert quarantine._zone_identifier("C:/file.bin") == (None, True)
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: io.BytesIO(b"x" * (quarantine.MAX_ZONE_BYTES + 1)))
    assert quarantine._zone_identifier("C:/file.bin") == (None, True)


@pytest.mark.skipif(os.name != "nt", reason="Windows file attributes")
@pytest.mark.parametrize("flag", RECALL_FLAGS)
def test_measure_does_not_open_cloud_placeholder(monkeypatch: pytest.MonkeyPatch, flag: int) -> None:
    monkeypatch.setattr(identity.os, "stat", lambda *args, **kwargs: SimpleNamespace(st_file_attributes=flag))
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: pytest.fail("cloud content opened"))
    result = identity.measure("C:/cloud.bin")
    assert result.code == "CLOUD_PLACEHOLDER" and result.identity is None


@pytest.mark.skipif(os.name != "nt", reason="Windows file attributes")
def test_metadata_revalidation_does_not_open_cloud_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity.os, "stat", lambda *args, **kwargs: SimpleNamespace(st_file_attributes=0x1000))
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: pytest.fail("cloud content opened"))
    expected = FileIdentity(None, None, None, 0, hashlib.sha256(b"").hexdigest(), None, None)
    result = identity.revalidate("C:/cloud.bin", expected, rehash=False)
    assert result.code == "CLOUD_PLACEHOLDER" and result.identity is None


@pytest.mark.parametrize("flag", RECALL_FLAGS)
def test_open_stream_is_not_read_after_cloud_attribute_check(monkeypatch: pytest.MonkeyPatch, flag: int) -> None:
    class Stream:
        def fileno(self) -> int:
            return 7

        def read(self, amount: int) -> bytes:
            pytest.fail("cloud content read")

    monkeypatch.setattr(identity, "os", SimpleNamespace(
        fstat=lambda descriptor: SimpleNamespace(st_file_attributes=flag)))
    result = identity.measure_stream(Stream(), "cloud.bin", max_bytes=1024)  # type: ignore[arg-type]
    assert result.code == "CLOUD_PLACEHOLDER" and result.identity is None


@pytest.mark.parametrize("flag", RECALL_FLAGS)
def test_discovery_records_cloud_gap(monkeypatch: pytest.MonkeyPatch, flag: int) -> None:
    info = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=flag | 0x400,
                           st_dev=1, st_ino=2, st_size=10)
    monkeypatch.setattr(scope.os, "stat", lambda *args, **kwargs: info)
    entry = scope.SourceEntry("watched", "cloud", "C:/cloud.bin")
    scan = scope.discover("deep", {"watched": lambda: (entry,)})
    assert list(scan) == []
    assert scan.report.reasons["cloud_placeholder"] == 1
    assert scan.report.gap_count == 1 and scan.report.queued == 0


def test_folder_walk_marks_cloud_before_opening_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    class Entry:
        name = "cloud.bin"
        path = "C:/folder/cloud.bin"

        def stat(self, *, follow_symlinks: bool) -> SimpleNamespace:
            return SimpleNamespace(st_file_attributes=0x400000)

        def is_symlink(self) -> bool:
            pytest.fail("cloud entry inspected further")

    class Scan:
        def __enter__(self) -> Scan:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def __iter__(self) -> Iterator[Entry]:
            return iter((Entry(),))

    monkeypatch.setattr(scope.os, "scandir", lambda path: Scan())
    entries = list(scope.walk_folder("C:/folder", "fixed_drive"))
    assert len(entries) == 1 and entries[0].reason == "cloud_placeholder"


@pytest.mark.skipif(os.name != "nt", reason="Windows handles")
@pytest.mark.parametrize("flag", RECALL_FLAGS)
def test_action_open_refuses_cloud_without_recall(monkeypatch: pytest.MonkeyPatch, flag: int) -> None:
    opened: list[int] = []
    closed: list[bool] = []
    target = SimpleNamespace(handle=7, close=lambda: closed.append(True))

    def fake_open(path: str, access: int, share: int, disposition: int, attributes: int,
                  mode: int, how: str) -> SimpleNamespace:
        opened.append(attributes)
        return target

    monkeypatch.setattr(winfile, "_open", fake_open)
    monkeypatch.setattr(winfile, "_file_attributes", lambda handle, path: flag)
    monkeypatch.setattr(winfile, "_reparse_tag", lambda *args: pytest.fail("cloud tag inspected"))
    with pytest.raises(winfile.TargetError) as error:
        winfile.open_target("C:/cloud.bin")
    assert error.value.code == "CLOUD_PLACEHOLDER"
    assert opened == [winfile.FILE_FLAG_OPEN_NO_RECALL] and closed == [True]


@pytest.mark.skipif(os.name != "nt", reason="Windows alternate data streams")
def test_restore_reports_failed_download_mark_write(tmp_path: Path, db,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "download.bin"
    path.write_bytes(BODY)
    with open(str(path) + ":Zone.Identifier", "w", encoding="utf-8") as stream:
        stream.write("[ZoneTransfer]\nZoneId=3\n")
    qid = quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(BODY).hexdigest()})
    monkeypatch.setattr(winfile.Target, "write_stream", lambda *args: (_ for _ in ()).throw(
        winfile.TargetError("FAILED")))
    restored = quarantine.restore(db, qid, trust=False)
    assert restored == path and restored.read_bytes() == BODY
    assert restored.zone_identifier_preserved is False


@pytest.mark.skipif(os.name != "nt", reason="Windows alternate data streams")
def test_restore_reports_preserved_download_mark(tmp_path: Path, db) -> None:
    path = tmp_path / "download.bin"
    path.write_bytes(BODY)
    with open(str(path) + ":Zone.Identifier", "w", encoding="utf-8") as stream:
        stream.write("[ZoneTransfer]\nZoneId=3\n")
    qid = quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(BODY).hexdigest()})
    restored = quarantine.restore(db, qid, trust=False)
    assert restored == path and restored.zone_identifier_preserved is True


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-based quarantine")
def test_restore_reports_unreadable_original_mark(tmp_path: Path, db,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "download.bin"
    path.write_bytes(BODY)
    monkeypatch.setattr(quarantine, "_zone_identifier", lambda path: (None, True))
    qid = quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(BODY).hexdigest()})
    restored = quarantine.restore(db, qid, trust=False)
    assert restored == path and restored.read_bytes() == BODY
    assert restored.zone_identifier_preserved is False


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-based quarantine")
def test_restore_reports_no_mark_when_none_existed(tmp_path: Path, db) -> None:
    path = tmp_path / "local.bin"
    path.write_bytes(BODY)
    qid = quarantine.quarantine(db, str(path), {"sha256": hashlib.sha256(BODY).hexdigest()})
    restored = quarantine.restore(db, qid, trust=False)
    assert restored == path and restored.zone_identifier_preserved is None


@pytest.mark.skipif(os.name != "nt", reason="Windows file attributes")
def test_a_placeholder_is_unknown_through_the_real_gate_and_never_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    from sentinel.gate_v2.contract import ScanRequest, VerdictCode
    from sentinel.gate_v2.core import CoreAdapter
    from sentinel.gate_v2.orchestrator import scan
    from sentinel.gate_v2.policy import RequiredStages

    path = tmp_path / "cloud.bin"
    path.write_bytes(b"content that must stay remote")
    # ARCHIVE is set on any new file, so a real file stands in for a placeholder.
    monkeypatch.setattr(identity, "RECALL_ATTRIBUTES", 0x20)
    request = ScanRequest(2, "scan", "f", str(path), None, "test", "single_file", "evidence-v1", "evidence-v1",
                          time.monotonic_ns() + 30_000_000_000, None, False)
    decision = scan(request, adapters=[CoreAdapter()], stages=RequiredStages(frozenset(("core",))),
                    gate_generation="t", auto_quarantine=True)
    assert decision.verdict is VerdictCode.UNKNOWN and not decision.trusted_clean
    assert "CLOUD_PLACEHOLDER" in decision.reason_codes


def test_a_path_derived_from_a_restored_file_is_a_plain_path(tmp_path: Path) -> None:
    restored = quarantine.RestoredPath(tmp_path / "x.bin", zone_identifier_preserved=True)
    assert restored.zone_identifier_preserved is True and str(restored) == str(tmp_path / "x.bin")
    assert type(restored.parent) is type(tmp_path) and type(restored / "a" / "b") is type(tmp_path)
    assert restored.joinpath("a", "b") == tmp_path / "x.bin" / "a" / "b"
