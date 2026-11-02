"""Quarantine: move a file out of reach, encoded so it can't be run or re-detected by accident."""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Any

from . import config
from .db import Database

# XOR keeps the stored bytes inert (no valid header, no matching signatures)
# without pretending to be encryption.
_KEY = bytes(range(0x5A, 0x5A + 64))


def _xor(data: bytes) -> bytes:
    if not data:
        return b""
    n = len(data)
    k = (_KEY * (n // len(_KEY) + 1))[:n]
    # Big-int XOR runs in C; a per-byte loop takes seconds on a 50 MB file.
    return (int.from_bytes(data, "little") ^ int.from_bytes(k, "little")).to_bytes(n, "little")


class QuarantineError(Exception):
    pass


def quarantine(db: Database, path: str, verdict: dict[str, Any]) -> str:
    src = Path(path)
    try:
        data = src.read_bytes()
    except OSError as e:
        raise QuarantineError(f"cannot read {src}: {e}") from e
    qid = uuid.uuid4().hex
    dest = config.quarantine_dir() / f"{qid}.qbin"
    dest.write_bytes(_xor(data))
    try:
        os.remove(src)
    except OSError as e:
        dest.unlink(missing_ok=True)
        raise QuarantineError(f"cannot remove {src} (in use?): {e}") from e
    db.add_quarantine(qid, str(src), hashlib.sha256(data).hexdigest(), len(data), verdict)
    return qid


def restore(db: Database, qid: str, *, trust: bool = True) -> Path:
    item = db.quarantine_item(qid)
    if not item:
        raise QuarantineError(f"no quarantine item {qid}")
    blob = config.quarantine_dir() / f"{qid}.qbin"
    try:
        data = _xor(blob.read_bytes())
    except OSError as e:
        raise QuarantineError(f"quarantine file missing: {e}") from e
    target = Path(item["original_path"])
    if target.exists():
        target = target.with_name(f"{target.stem} (restored){target.suffix}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
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
