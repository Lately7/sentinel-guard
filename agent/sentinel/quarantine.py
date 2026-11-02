"""Quarantine: move a file out of reach, encoded so it can't be run or re-detected by accident.

Order of operations matters: claim the file (rename in place), verify it is
still the content that was scanned, write the encoded copy, record it, and only
then delete the original. Any failure undoes the earlier steps.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from . import config
from .db import Database

# XOR keeps the stored bytes inert (no valid header, no matching signatures)
# without pretending to be encryption.
_KEY = bytes(range(0x5A, 0x5A + 64))
CHUNK = 1024 * 1024  # multiple of len(_KEY), so the key phase restarts at each chunk


class QuarantineError(Exception):
    pass


def _xor_chunk(data: bytes) -> bytes:
    n = len(data)
    if not n:
        return b""
    k = (_KEY * (n // len(_KEY) + 1))[:n]
    # Big-int XOR runs in C; a per-byte loop takes seconds on a 50 MB file.
    return (int.from_bytes(data, "little") ^ int.from_bytes(k, "little")).to_bytes(n, "little")


def _copy_xor(src: Path, dest: Path) -> str:
    """Stream src -> dest XOR-encoded (or decoded: XOR is symmetric). Returns sha256 of the plain bytes."""
    h = hashlib.sha256()
    decoding = src.suffix == ".qbin"
    with src.open("rb") as fi, dest.open("xb") as fo:
        while chunk := fi.read(CHUNK):
            out = _xor_chunk(chunk)
            h.update(out if decoding else chunk)
            fo.write(out)
    return h.hexdigest()


def quarantine(db: Database, path: str, verdict: dict[str, Any]) -> str:
    src = Path(path)
    qid = uuid.uuid4().hex
    claimed = src.with_name(f"{src.name}.sentinel-{qid[:8]}.claim")
    dest = config.quarantine_dir() / f"{qid}.qbin"
    try:
        # Renaming first means nobody can swap the file under us between the
        # hash check and the delete; it also stops the file being opened by name.
        os.replace(src, claimed)
    except OSError as e:
        raise QuarantineError(f"cannot claim {src} (in use or removed?): {e}") from e
    try:
        sha = _copy_xor(claimed, dest)
        expected = verdict.get("sha256")
        if expected and sha != expected:
            raise QuarantineError(f"{src} changed after it was scanned; it will be rescanned")
        size = claimed.stat().st_size
        db.add_quarantine(qid, str(src), sha, size, verdict)
        try:
            os.remove(claimed)
        except OSError as e:
            db.remove_quarantine(qid)
            raise QuarantineError(f"cannot remove {src}: {e}") from e
    except (QuarantineError, OSError, sqlite3.Error) as e:
        dest.unlink(missing_ok=True)
        try:
            if claimed.exists() and not src.exists():
                os.replace(claimed, src)
        except OSError:
            pass
        if isinstance(e, QuarantineError):
            raise
        raise QuarantineError(f"quarantine of {src} failed: {e}") from e
    return qid


def _unique_target(original: Path) -> Path:
    if not original.exists():
        return original
    for i in range(1, 1000):
        cand = original.with_name(f"{original.stem} (restored{'' if i == 1 else f' {i}'}){original.suffix}")
        if not cand.exists():
            return cand
    raise QuarantineError(f"no free name to restore {original}")


def restore(db: Database, qid: str, *, trust: bool = True) -> Path:
    item = db.quarantine_item(qid)
    if not item:
        raise QuarantineError(f"no quarantine item {qid}")
    blob = config.quarantine_dir() / f"{qid}.qbin"
    if not blob.is_file():
        raise QuarantineError("quarantine file missing")
    original = Path(item["original_path"])
    try:
        original.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(3):
            target = _unique_target(original)
            try:
                sha = _copy_xor(blob, target)  # "xb": never overwrites a file that appeared meanwhile
                break
            except FileExistsError:
                continue
        else:
            raise QuarantineError(f"no free name to restore {original}")
    except OSError as e:
        raise QuarantineError(f"cannot restore to {original}: {e}") from e
    if sha != item["sha256"]:
        target.unlink(missing_ok=True)
        raise QuarantineError("quarantined copy is damaged (hash mismatch)")
    if trust:
        # Without this the watcher would quarantine the file again immediately.
        db.allow_hash(item["sha256"])
        db.bump_generation()
    blob.unlink(missing_ok=True)
    db.remove_quarantine(qid)
    return target


def delete(db: Database, qid: str) -> None:
    (config.quarantine_dir() / f"{qid}.qbin").unlink(missing_ok=True)
    db.remove_quarantine(qid)
