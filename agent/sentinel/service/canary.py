"""Harmless document canaries in explicitly supplied owner-approved roots."""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MAX_CANARIES = 256
MAX_SIZE = 64 * 1024
def _pdf() -> bytes:
    content = b"BT /F1 12 Tf 72 720 Td (Household notes) Tj ET"
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    )
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + obj + b"\nendobj\n"
    start = len(out)
    out += f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode()
    for offset in offsets[1:]:
        out += f"{offset:010} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n".encode()
    return bytes(out)


def _png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\x88\xaa\xcc")) + chunk(b"IEND", b""))


_DOCUMENTS = {
    ".txt": "Ghi chú trong tuần\nLịch hẹn và việc gia đình.\n".encode("utf-8"),
    ".csv": "ngày,mục,số tiền\n2026-01-01,gia đình,12\n".encode("utf-8"),
    ".pdf": _pdf(),
    ".png": _png(),
}


@dataclass(frozen=True)
class Placement:
    root: Path
    relative: Path
    content: bytes

    @property
    def path(self) -> Path:
        return self.root / self.relative


@dataclass(frozen=True)
class Record:
    path: Path
    device: int
    file_id: int
    size: int
    sha256: str


@dataclass(frozen=True)
class Check:
    status: str  # INTACT | CONTENT_CHANGED | REPLACED | MISSING | GAP
    path: Path
    reason: str = ""


def placement_plan(roots: Iterable[Path], *, per_root: int = 3) -> tuple[Placement, ...]:
    if not 1 <= per_root <= 4:
        raise ValueError("per_root out of range")
    plan: list[Placement] = []
    names = (("Archive/household-notes.txt", ".txt"),
             ("Receipts/2026/expenses.csv", ".csv"),
             ("Projects/meeting-notes.pdf", ".pdf"),
             ("Archive/2025/planning.csv", ".csv"))
    for root in roots:
        selected = names
        if Path(root).name.lower() == "pictures":
            selected = (("Albums/2026/family-photo.png", ".png"), *names[1:])
        for relative, suffix in selected[:per_root]:
            plan.append(Placement(Path(root), Path(relative), _DOCUMENTS[suffix]))
    if len(plan) > MAX_CANARIES:
        raise ValueError("too many canaries")
    return tuple(plan)


def _safe_root(root: Path) -> Path:
    if not root.is_dir() or _reparse(root):
        raise ValueError("root must be an existing ordinary directory")
    resolved = root.resolve(strict=True)
    if resolved == resolved.anchor or str(resolved) == resolved.anchor:
        raise ValueError("volume root is not a canary root")
    return resolved


def _reparse(path: Path) -> bool:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)


def _safe_target(placement: Placement) -> Path:
    root = _safe_root(placement.root)
    relative = placement.relative
    if relative.is_absolute() or not relative.parts or any(p in (".", "..") for p in relative.parts):
        raise ValueError("canary path escapes root")
    target = root / relative
    if not target.is_relative_to(root) or target == root:
        raise ValueError("canary path escapes root")
    current = root
    for component in relative.parts[:-1]:
        current /= component
        if current.exists() and (_reparse(current) or not current.is_dir()):
            raise ValueError("unsafe canary parent")
    return target


def create(placement: Placement) -> Record:
    """Creates a new ordinary file; caller chooses roots and protects the returned record."""
    target = _safe_target(placement)
    if len(placement.content) > MAX_SIZE or not placement.content:
        raise ValueError("invalid canary size")
    if target.suffix.lower() not in _DOCUMENTS:
        raise ValueError("unsupported harmless document type")
    target.parent.mkdir(parents=True, exist_ok=True)
    if _safe_target(placement).parent.resolve() != target.parent or _reparse(target):
        raise ValueError("symlink target")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(placement.content)
            stream.flush()
            os.fsync(fd)
        st = os.fstat(fd)
    finally:
        os.close(fd)
    return Record(target, st.st_dev, st.st_ino, st.st_size,
                  hashlib.sha256(placement.content).hexdigest())


def revalidate(record: Record) -> Check:
    try:
        st = record.path.lstat()
        if not stat.S_ISREG(st.st_mode):
            return Check("REPLACED", record.path, "not_regular")
        if (st.st_dev, st.st_ino) != (record.device, record.file_id):
            return Check("REPLACED", record.path, "file_id")
        if st.st_size > MAX_SIZE:
            return Check("CONTENT_CHANGED", record.path, "size_cap")
        with record.path.open("rb") as stream:
            data = stream.read(MAX_SIZE + 1)
        if len(data) != record.size or hashlib.sha256(data).hexdigest() != record.sha256:
            return Check("CONTENT_CHANGED", record.path)
        return Check("INTACT", record.path)
    except FileNotFoundError:
        return Check("MISSING", record.path)
    except OSError as exc:
        return Check("GAP", record.path, type(exc).__name__)
