"""File type identification from magic bytes, and name-based deception checks."""

from __future__ import annotations

import unicodedata

from .verdict import Finding, Severity

EXECUTABLE_EXTS = frozenset(
    ".exe .scr .com .pif .cpl .msi .msp .dll .sys .jar .lnk .url .reg .appref-ms "
    ".bat .cmd .ps1 .psm1 .vbs .vbe .js .jse .wsf .wsh .hta .msc .scf .application".split()
)
SCRIPT_EXTS = frozenset(".bat .cmd .ps1 .psm1 .vbs .vbe .js .jse .wsf .wsh .hta .sh .py".split())
DECOY_EXTS = frozenset(
    ".pdf .doc .docx .xls .xlsx .ppt .pptx .rtf .txt .csv .odt "
    ".jpg .jpeg .png .gif .bmp .webp .heic .mp3 .mp4 .avi .mkv .mov .wav".split()
)
ARCHIVE_EXTS = frozenset(".zip .rar .7z .gz .tgz .iso .img .cab .tar".split())

# Bidirectional control characters let "photo‮gpj.exe" render as "photoexe.jpg".
BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩‎‏")


def sniff(head: bytes) -> str:
    try:
        if len(head) >= 2 and head[:2] == b"MZ":
            return "pe"
        if head[:4] == b"\x7fELF":
            return "elf"
        if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            return "macho"
        if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            return "zip"
        if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return "ole"
        if head[:5] == b"%PDF-":
            return "pdf"
        if head[:6] in (b"Rar!\x1a\x07",):
            return "rar"
        if head[:6] == b"7z\xbc\xaf\x27\x1c":
            return "7z"
        if head[:2] == b"\x1f\x8b":
            return "gzip"
        if head[:4] == b"L\x00\x00\x00" and head[4:20] == bytes.fromhex("0114020000000000c000000000000046"):
            return "lnk"
        if head[:8] == b"\x89PNG\r\n\x1a\n" or head[:3] == b"\xff\xd8\xff" or head[:6] in (b"GIF87a", b"GIF89a"):
            return "image"
        if head[:2] == b"#!":
            return "script"
        if _looks_textual(head):
            return "text"
    except Exception:  # sniffing hostile bytes must never fail the scan
        pass
    return "unknown"


def _looks_textual(head: bytes) -> bool:
    if not head:
        return False
    sample = head[:4096]
    if b"\x00" in sample and not (sample.startswith(b"\xff\xfe") or sample.startswith(b"\xfe\xff")):
        return False
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    return printable / len(sample) > 0.95


def _exts(name: str) -> list[str]:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    parts = base.split(".")
    if len(parts) < 2:
        return []
    return ["." + p.strip().lower() for p in parts[1:]]


def extension(name: str) -> str:
    e = _exts(name)
    return e[-1] if e else ""


def check_name(name: str, head: bytes) -> list[Finding]:
    findings: list[Finding] = []
    try:
        kind = sniff(head)
        exts = _exts(name)
        last = exts[-1] if exts else ""

        if any(ch in BIDI_CONTROLS for ch in name):
            findings.append(Finding("filetype", "filetype.rtlo", Severity.HIGH,
                                    "file name contains bidirectional override characters that disguise its extension", 40))

        if len(exts) >= 2 and last in EXECUTABLE_EXTS and exts[-2] in DECOY_EXTS:
            findings.append(Finding("filetype", "filetype.double_extension", Severity.MEDIUM,
                                    f"executable '{last}' hidden behind '{exts[-2]}'", 25))
        elif last in EXECUTABLE_EXTS and _padded_before_ext(name):
            findings.append(Finding("filetype", "filetype.padded_name", Severity.MEDIUM,
                                    "long run of spaces before the extension hides it in Explorer", 25))

        if kind == "pe" and last in DECOY_EXTS:
            findings.append(Finding("filetype", "filetype.mismatch", Severity.MEDIUM,
                                    f"Windows executable content with a '{last}' extension", 25))

        if kind in ("pe", "lnk", "script") or last in EXECUTABLE_EXTS:
            findings.append(Finding("filetype", "filetype.executable", Severity.INFO,
                                    f"executable content ({kind}, {last or 'no extension'})", 0))
    except Exception:
        pass
    return findings


def _padded_before_ext(name: str) -> bool:
    base = name.rsplit(".", 1)[0]
    trailing = 0
    for ch in reversed(base):
        # U+2800 (braille blank) renders as empty space but is not category Zs.
        if unicodedata.category(ch) == "Zs" or ch == "⠀":
            trailing += 1
        else:
            break
    return trailing >= 3


def is_executable_kind(kind: str, name: str) -> bool:
    return kind in ("pe", "elf", "macho", "lnk", "script") or extension(name) in EXECUTABLE_EXTS
