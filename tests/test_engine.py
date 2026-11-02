from __future__ import annotations

import hashlib
import io
import os
import random
import zipfile

from conftest import EICAR, MARKER
from sentinel.engine import filetype
from sentinel.engine.signatures import EICAR_SHA256
from sentinel.engine.verdict import CLEAN, MALICIOUS, SUSPICIOUS, Finding, Severity, Verdict


def test_eicar_hash_constant_matches_the_test_file():
    assert hashlib.sha256(EICAR).hexdigest() == EICAR_SHA256


def test_eicar_in_memory_is_malicious(scanner):
    v = scanner.scan_bytes(EICAR, "eicar.com")
    assert v.label == MALICIOUS
    assert any(f.rule == "eicar.test_file" for f in v.findings)


def test_plain_text_is_clean(scanner):
    v = scanner.scan_bytes(b"hello world\n" * 100, "notes.txt")
    assert v.label == CLEAN and v.score == 0


def test_eicar_inside_zip_is_found(scanner):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "nothing here")
        zf.writestr("inner/eicar.com", EICAR)
    v = scanner.scan_bytes(buf.getvalue(), "bundle.zip")
    assert v.label == MALICIOUS
    assert any("inner/eicar.com" in f.detail for f in v.findings)


def test_nested_zip_depth_is_bounded(scanner):
    data = EICAR
    for i in range(6):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(f"layer{i}.bin", data)
        data = buf.getvalue()
    # Must terminate quickly and not raise, whatever it finds.
    scanner.scan_bytes(data, "deep.zip")


def test_corrupt_zip_does_not_raise(scanner):
    v = scanner.scan_bytes(b"PK\x03\x04" + os.urandom(500), "broken.zip")
    assert v.label in (CLEAN, SUSPICIOUS)


def test_marker_rule_detects_file_on_disk(scanner, tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"padding " * 50 + MARKER + b" trailer")
    v = scanner.scan_file(p)
    assert v.label == MALICIOUS
    assert v.path == str(p)


def test_scan_cache_is_invalidated_by_generation(scanner, db, tmp_path):
    p = tmp_path / "x.txt"
    p.write_bytes(b"benign")
    first = scanner.scan_file(p)
    assert first.label == CLEAN
    db.add_hashes([(first.sha256, "testfeed", "Test.Sample")])
    assert scanner.scan_file(p).label == CLEAN  # cached under the old generation
    db.bump_generation()
    again = scanner.scan_file(p)
    assert again.label == MALICIOUS
    assert any(f.rule == "hash.testfeed" for f in again.findings)


def test_allowlisted_hash_is_clean(scanner, db, tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(MARKER)
    db.allow_hash(hashlib.sha256(MARKER).hexdigest())
    assert scanner.scan_file(p).label == CLEAN


def test_unreadable_path_is_skipped_not_raised(scanner, tmp_path):
    v = scanner.scan_file(tmp_path / "missing.exe")
    assert v.skipped and v.label == CLEAN


def test_random_pe_like_bytes_never_raise(scanner):
    rnd = random.Random(1234)
    for _ in range(200):
        blob = b"MZ" + bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 2048)))
        scanner.scan_bytes(blob, "x.exe")


# -- verdict -----------------------------------------------------------------

def test_verdict_labels():
    def v(*scores, critical=False):
        out = Verdict("n", "h", 1)
        for s in scores:
            out.findings.append(Finding("t", "r", Severity.MEDIUM, "d", s))
        if critical:
            out.findings.append(Finding("t", "c", Severity.CRITICAL, "d", 0))
        return out

    assert v(10).label == CLEAN
    assert v(20, 15).label == SUSPICIOUS
    assert v(40, 40).label == MALICIOUS
    assert v(critical=True).label == MALICIOUS
    assert v(90, 90).score == 100


# -- file type ---------------------------------------------------------------

def test_sniff_magic():
    assert filetype.sniff(b"MZ\x90\x00") == "pe"
    assert filetype.sniff(b"PK\x03\x04rest") == "zip"
    assert filetype.sniff(b"%PDF-1.7") == "pdf"
    assert filetype.sniff(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") == "ole"
    assert filetype.sniff(b"#!/bin/sh\n") == "script"
    assert filetype.sniff(b"plain text") == "text"
    assert filetype.sniff(b"") == "unknown"


def _rules(name, head=b"text"):
    return {f.rule for f in filetype.check_name(name, head)}


def test_double_extension_and_padding():
    assert "filetype.double_extension" in _rules("invoice.pdf.exe", b"MZ")
    assert "filetype.double_extension" in _rules("photo.JPG.scr", b"MZ")
    assert "filetype.padded_name" in _rules("report" + " " * 30 + ".exe", b"MZ")
    assert "filetype.double_extension" not in _rules("setup.exe", b"MZ")
    assert "filetype.double_extension" not in _rules("archive.tar.gz", b"\x1f\x8b")


def test_bidi_override_and_mismatch():
    assert "filetype.rtlo" in _rules("photo‮gpj.exe", b"MZ")
    assert "filetype.mismatch" in _rules("cv.pdf", b"MZ\x90\x00")
    assert "filetype.mismatch" not in _rules("cv.pdf", b"%PDF-1.4")


def test_check_name_never_raises_on_odd_input():
    for name in ("", ".", "....", "\x00\x00", "a" * 5000, "名前.exe"):
        filetype.check_name(name, os.urandom(64))
