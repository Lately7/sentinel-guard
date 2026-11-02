"""Desired behaviour for open known issues (RT registry in REVIEWS.md).

Each test states what the code SHOULD do and is marked xfail(strict=True):
it fails today, and the suite turns red the moment a fix lands, so the
marker has to be removed together with the fix. None of them legitimises the
current behaviour.
"""

from __future__ import annotations

import pytest

from conftest import MARKER
from sentinel import config, quarantine
from sentinel.engine.clamav import finding_for
from sentinel.engine.verdict import Severity
from sentinel.protection import act_on


@pytest.mark.xfail(strict=True, reason="RT-001: weak ClamAV names are treated as conclusive")
def test_weak_clamav_name_is_not_conclusive():
    # Seen on a harmless ZIP whose member was named invoice.pdf.exe.
    assert finding_for("Win.Trojan.Suspect-34").severity < Severity.CRITICAL


def test_restore_creates_a_path_and_hash_exception_only(db, scanner, tmp_path):
    p = tmp_path / "bad.bin"
    p.write_bytes(b"head " + MARKER + b" tail")
    out = act_on(db, scanner.scan_file(p), config.Settings(), "scan")
    restored = quarantine.restore(db, out["quarantine_id"])
    copy = tmp_path / "elsewhere" / "copy.bin"
    copy.parent.mkdir()
    copy.write_bytes(restored.read_bytes())
    # Restoring one file is not "trust these bytes everywhere".
    assert scanner.scan_file(copy).label == "malicious"
