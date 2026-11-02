"""Quarantine: move a file out of reach, encoded so it can't be run or re-detected by accident.

Order of operations matters: open the file so it can't be written, verify it is
still what was scanned, write the encoded copy, record it, and only then let go
of the original. Any failure before that last step leaves the file where it was;
a crash in between is settled by reconcile() on the next start.
"""

from __future__ import annotations

import hashlib
import json
import logging
import ntpath
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO

from . import config
from .db import Database
from .gate_v2 import identity, winfile
from .gate_v2.contract import FileIdentity
from .gate_v2.winfile import TargetError

log = logging.getLogger(__name__)

# XOR keeps the stored bytes inert (no valid header, no matching signatures)
# without pretending to be encryption.
_KEY = bytes(range(0x5A, 0x5A + 64))
CHUNK = 1024 * 1024  # multiple of len(_KEY), so the key phase restarts at each chunk
MAX_ZONE_BYTES = 4096
# A journal row lives for a moment around the deletion; one older than this was
# left by a process that died, not by another process still acting.
JOURNAL_GRACE_SECONDS = 60.0

# Two scans of one file must not both claim it.
_action_lock = threading.RLock()
# NTFS allows lone surrogates in names and SQLite's UTF-8 does not. They are kept
# as private-use characters, so the file goes back under its exact name.
_KEPT_SHIFT = 0xF0000 - 0xD800


def kept_path(path: str) -> str:
    return "".join(chr(ord(c) + _KEPT_SHIFT) if 0xD800 <= ord(c) <= 0xDFFF else c for c in path)


def real_path(path: str) -> str:
    return "".join(chr(ord(c) - _KEPT_SHIFT) if 0xF0000 <= ord(c) <= 0xF07FF else c for c in path)


class QuarantineError(Exception):
    def __init__(self, message: str, code: str = "FAILED") -> None:
        self.code = code
        super().__init__(message)


def _xor_chunk(data: bytes) -> bytes:
    n = len(data)
    if not n:
        return b""
    k = (_KEY * (n // len(_KEY) + 1))[:n]
    # Big-int XOR runs in C; a per-byte loop takes seconds on a 50 MB file.
    return (int.from_bytes(data, "little") ^ int.from_bytes(k, "little")).to_bytes(n, "little")


def _xor_stream(src: BinaryIO, dest: BinaryIO, size: int, *, decoding: bool) -> str:
    """Stream src -> dest XOR-encoded (or decoded: XOR is symmetric). Returns sha256 of the plain bytes.

    Copies exactly the size measured up front: it must neither run forever nor
    silently include bytes that were never scanned.
    """
    h = hashlib.sha256()
    remaining = size
    while remaining > 0:
        chunk = src.read(min(CHUNK, remaining))
        if not chunk:
            break
        remaining -= len(chunk)
        out = _xor_chunk(chunk)
        h.update(out if decoding else chunk)
        view = memoryview(out)
        while view:  # unbuffered writes may be partial
            view = view[dest.write(view):]
    if remaining:
        raise QuarantineError("the file ended early while being copied", "CHANGED")
    return h.hexdigest()


def _copy_xor(src: winfile.Target, dest: Path) -> str:
    with dest.open("xb") as out:
        sha = _xor_stream(src.stream, out, src.size, decoding=False)
        # On the disk before the original goes: a power cut must not cost both.
        out.flush()
        os.fsync(out.fileno())
    return sha


def _zone_identifier(path: str) -> str | None:
    # A restored download must stay marked as one, or restoring would switch off
    # SmartScreen for it.
    try:
        with open(path + ":Zone.Identifier", "rb") as stream:
            return stream.read(MAX_ZONE_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None


def _open_names(path: str, expected: FileIdentity | None) -> list[winfile.Target]:
    """Every name of the file, opened: removing one hard link leaves the bytes reachable."""
    names = [winfile.open_target(path)]
    try:
        first = names[0]
        if not winfile.same_path(first.path, expected.canonical_path if expected and expected.canonical_path else path):
            raise QuarantineError(f"{path} now leads somewhere else", "CHANGED")
        # Which file, not when it was last touched: the copy below proves the bytes,
        # and a timestamp must not be a way to stay out of quarantine.
        if expected is not None and (*first.key, first.size) != (expected.volume_serial, expected.file_id_hex, expected.size):
            raise QuarantineError(f"{path} changed after it was scanned; it will be rescanned", "CHANGED")
        for name in first.other_names():
            other = winfile.open_target(name)
            names.append(other)
            if other.key != first.key:
                raise QuarantineError(f"{name} is no longer the same file", "CHANGED")
        # A user's own file is not the system's, wherever a link of it was put:
        # otherwise one hard link into a system folder would be a way out of here.
        if any(winfile.is_protected(n.path) for n in names) and first.system_owned():
            raise QuarantineError(f"{path} is in a system folder and is not touched", "PROTECTED_PATH")
        return names
    except BaseException:
        for n in names:
            n.close()
        raise


def quarantine(db: Database, path: str, verdict: dict[str, Any], *, expected: FileIdentity | None = None) -> str:
    # Opening can wait for as long as a hostile oplock holder likes, so none of
    # it happens under the lock: one such file must not hold up every other.
    src = Path(path)
    zone = _zone_identifier(path)
    try:
        names = _open_names(path, expected)
    except TargetError as e:
        raise QuarantineError(f"cannot open {src} (in use or removed?): {e}", e.code) from e
    with _action_lock:
        return _quarantine(db, src, names, verdict, expected, zone)


def _quarantine(db: Database, src: Path, names: list[winfile.Target], verdict: dict[str, Any],
                expected: FileIdentity | None, zone: str | None) -> str:
    qid = uuid.uuid4().hex
    dest = config.quarantine_dir() / f"{qid}.qbin"
    recorded = False
    first = names[0]
    held = [n.path for n in names]
    key = first.key
    try:
        if first.gone():
            raise QuarantineError(f"{src} is already gone", "MISSING")
        sha = _copy_xor(first, dest)
        wanted = verdict.get("sha256") or (expected.sha256 if expected else None)
        if wanted and sha != wanted:
            raise QuarantineError(f"{src} changed after it was scanned; it will be rescanned", "CHANGED")
        with db.transaction():
            db.open_action(qid, kept_path(str(src)), sha)
            db.add_quarantine(qid, kept_path(str(src)), sha, first.size,
                              {**verdict, "zone_identifier": zone} if zone else verdict)
        recorded = True
        try:
            for n in names:
                n.mark_delete()
        except TargetError as e:
            # Undone while the handles are open: nothing has been deleted yet.
            for n in names:
                try:
                    n.mark_delete(False)
                except TargetError:
                    log.exception("could not clear the deletion mark of %s", n.path)
            raise QuarantineError(f"cannot remove {src}: {e}", "IN_USE") from e
        for n in names:
            n.close()
        # What counts is what is there now: a handle opened before ours can clear
        # the mark right up to the end, and "quarantined" must not be a claim.
        if any(_same_file_here(path, key) for path in held):
            raise QuarantineError(f"{src} is still there", "IN_USE")
    except (QuarantineError, OSError, sqlite3.Error, TargetError, ValueError) as e:
        if recorded:
            with db.transaction():
                db.remove_quarantine(qid)
                db.close_action(qid)
        dest.unlink(missing_ok=True)
        if isinstance(e, QuarantineError):
            raise
        raise QuarantineError(f"quarantine of {src} failed: {e}") from e
    finally:
        for n in names:
            n.close()
    db.close_action(qid)
    return qid


def _same_file_here(path: str, key: tuple[int, str]) -> bool:
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return (info.st_dev, f"{info.st_ino:032x}") == key


def reconcile(db: Database, *, grace: float = JOURNAL_GRACE_SECONDS) -> int:
    """Settles actions a crash left open, so no file is quarantined twice or lost."""
    settled = 0
    for row in db.open_actions(time.time() - grace):
        qid = row["qid"]
        blob = config.quarantine_dir() / f"{qid}.qbin"
        found = identity.measure(real_path(row["path"]), max_bytes=config.MAX_SCAN_BYTES)
        with _action_lock:
            if found.ok and found.identity is not None and found.identity.sha256 == row["sha256"]:
                # The deletion never ran: the file is where it was, the copy is not needed.
                with db.transaction():
                    db.remove_quarantine(qid)
                    db.close_action(qid)
                blob.unlink(missing_ok=True)
            else:
                with db.transaction():
                    if not blob.is_file():
                        db.remove_quarantine(qid)
                    db.close_action(qid)
        settled += 1
    return settled


def _unique_target(original: Path) -> Path:
    if not original.exists():
        return original
    for i in range(1, 1000):
        cand = original.with_name(f"{original.stem} (restored{'' if i == 1 else f' {i}'}){original.suffix}")
        if not cand.exists():
            return cand
    raise QuarantineError(f"no free name to restore {original}")


def _create_target(original: Path) -> tuple[Path, winfile.Target]:
    try:
        winfile.make_parents(str(original))
        for _ in range(3):
            target = _unique_target(original)
            try:
                return target, winfile.create_new(str(target))  # never overwrites a file that appeared meanwhile
            except FileExistsError:
                continue
    except TargetError as e:
        raise QuarantineError(f"cannot restore to {original}: {e}", e.code) from e
    except OSError as e:
        raise QuarantineError(f"cannot restore to {original}: {e}") from e
    raise QuarantineError(f"no free name to restore {original}")


def restore(db: Database, qid: str, *, trust: bool = True) -> Path:
    with _action_lock:
        return _restore(db, qid, trust)


def _restore(db: Database, qid: str, trust: bool) -> Path:
    item = db.quarantine_item(qid)
    if not item:
        raise QuarantineError(f"no quarantine item {qid}")
    blob = config.quarantine_dir() / f"{qid}.qbin"
    if not blob.is_file():
        raise QuarantineError("quarantine file missing")
    target, created = _create_target(Path(real_path(item["original_path"])))
    try:
        try:
            with blob.open("rb") as stored:
                sha = _xor_stream(stored, created.stream, blob.stat().st_size, decoding=True)
            if sha != item["sha256"]:
                raise QuarantineError("quarantined copy is damaged (hash mismatch)", "DAMAGED")
            # One transaction: either the item is gone from quarantine *and*
            # excepted, or nothing changed and the restored copy is removed again,
            # so a retry can't produce a duplicate.
            with db.transaction():
                if trust:
                    # Without this the watcher would quarantine the file again at once.
                    # This file at this path only: restoring is not trusting these
                    # bytes everywhere (RT-002); trust is its own explicit action.
                    db.add_restore_exception(str(target), item["sha256"])
                    db.bump_generation()
                db.remove_quarantine(qid)
        except (QuarantineError, OSError, sqlite3.Error) as e:
            created.mark_delete()
            if isinstance(e, QuarantineError):
                raise
            raise QuarantineError(f"restore could not be finished: {e}") from e
        _put_back_zone(created, target, item)
    finally:
        created.close()
    blob.unlink(missing_ok=True)  # an orphaned blob after this point is harmless
    return target


def _put_back_zone(created: winfile.Target, target: Path, item: dict[str, Any]) -> None:
    try:
        zone = json.loads(item["verdict"]).get("zone_identifier")
        if isinstance(zone, str):
            created.write_stream(":Zone.Identifier", zone.encode("utf-8"))
    except (TargetError, ValueError, AttributeError):
        log.warning("could not put the download mark back on %s", ntpath.basename(str(target)))


def delete(db: Database, qid: str) -> None:
    (config.quarantine_dir() / f"{qid}.qbin").unlink(missing_ok=True)
    db.remove_quarantine(qid)
