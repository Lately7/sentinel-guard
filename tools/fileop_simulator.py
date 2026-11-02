"""Reversible file operations confined to a harness-created disposable corpus."""

from __future__ import annotations

import os
import secrets
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

MARKER = ".sentinel-fileop-harness"
STATE = ".sentinel-fileop-state"
KEY = b"SentinelGuard harmless fixed test key v1"
CORPUS_SIZE = 16


@dataclass(frozen=True)
class Harness:
    directory: Path
    token: str


@dataclass(frozen=True)
class Event:
    at: float
    path: str
    operation: str


def _network(path: Path) -> bool:
    value = str(path)
    return value.startswith(("\\\\", "//")) or value.startswith("\\?\\UNC\\")


def _reparse(path: Path) -> bool:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)


def _check_ancestors(path: Path) -> None:
    if _network(path) or not path.is_absolute():
        raise ValueError("local absolute path required")
    current = path
    while True:
        if _reparse(current):
            raise ValueError("reparse point refused")
        if current == current.parent:
            break
        current = current.parent


def _profile_roots() -> set[Path]:
    roots = {Path.home().resolve()}
    for name in ("USERPROFILE",):
        value = os.environ.get(name)
        if value:
            roots.add(Path(value).resolve())
    return roots


def _personal_roots() -> tuple[Path, ...]:
    home = Path.home().resolve()
    return tuple(home / name for name in ("Desktop", "Documents", "Downloads", "Pictures", "Videos"))


def _check_directory(path: Path) -> Path:
    _check_ancestors(path)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("directory unavailable") from exc
    if (resolved == Path(resolved.anchor) or resolved in _profile_roots()
            or any(resolved.is_relative_to(root) for root in _personal_roots())):
        raise ValueError("root or profile directory refused")
    if _network(resolved) or not resolved.is_dir():
        raise ValueError("ordinary local directory required")
    return resolved


def create_harness(parent: Path, name: str = "sentinel-fileop-test") -> Harness:
    parent = _check_directory(Path(parent))
    if not name or name in (".", "..") or Path(name).name != name:
        raise ValueError("invalid harness name")
    directory = parent / name
    directory.mkdir(mode=0o700, exist_ok=False)
    token = secrets.token_hex(24)
    (directory / MARKER).write_text(token, encoding="ascii")
    return Harness(directory, token)


def validate(harness: Harness) -> Path:
    directory = _check_directory(harness.directory)
    marker = directory / MARKER
    if _reparse(marker) or not marker.is_file():
        raise ValueError("missing harness marker")
    if marker.read_text(encoding="ascii") != harness.token or len(harness.token) != 48:
        raise ValueError("invalid harness marker")
    for item in directory.rglob("*"):
        if _reparse(item):
            raise ValueError("reparse point refused")
    return directory


def seed(harness: Harness) -> tuple[Path, ...]:
    directory = validate(harness)
    corpus = directory / "corpus"
    baseline = directory / "baseline"
    corpus.mkdir(exist_ok=False)
    baseline.mkdir(exist_ok=False)
    paths: list[Path] = []
    for i in range(CORPUS_SIZE):
        subdir = corpus / ("a" if i % 2 else "b")
        subdir.mkdir(exist_ok=True)
        path = subdir / f"document-{i:02}.txt"
        data = f"Harmless test document {i:02}\n".encode("ascii") * 4
        path.write_bytes(data)
        clean = baseline / subdir.name
        clean.mkdir(exist_ok=True)
        (clean / path.name).write_bytes(data)
        paths.append(path)
    return tuple(paths)


def transform(data: bytes) -> bytes:
    # XOR is symmetric, so a second pass restores the exact original bytes.
    return bytes(value ^ KEY[i % len(KEY)] for i, value in enumerate(data))


def run(harness: Harness, *, mode: str = "overwrite", order: str = "forward",
        skip_canaries: bool = False, delay: float = 0.0, workers: int = 1,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep) -> tuple[Event, ...]:
    directory = validate(harness)
    if mode not in ("overwrite", "rename", "partial") or order not in ("forward", "reverse"):
        raise ValueError("unsupported simulation mode")
    if delay < 0 or delay > 5 or not 1 <= workers <= 4:
        raise ValueError("simulation rate or worker count out of range")
    corpus = directory / "corpus"
    if not corpus.is_dir():
        raise ValueError("corpus missing; seed first")
    paths = sorted(corpus.rglob("document-*.txt"), reverse=order == "reverse")
    if len(paths) != CORPUS_SIZE:
        raise ValueError("corpus incomplete")
    state = directory / STATE
    if state.exists():
        raise ValueError("restore previous run first")
    def operate(index_path: tuple[int, Path]) -> tuple[Path, list[Event]] | None:
        index, path = index_path
        if skip_canaries and index in (2, 9):
            return None
        if _reparse(path) or not path.is_file() or not path.resolve().is_relative_to(directory):
            raise ValueError("unsafe corpus entry")
        original = path.read_bytes()
        events = [Event(clock(), str(path), "read")]
        changed = transform(original)
        if mode == "rename":
            sibling = path.with_suffix(".new")
            if sibling.exists():
                raise ValueError("stale temporary output")
            sibling.write_bytes(changed)
            events.append(Event(clock(), str(sibling), "write_new"))
            sibling.replace(path)
            events.append(Event(clock(), str(path), "rename_replace"))
        elif mode == "partial":
            with path.open("r+b") as stream:
                split = len(changed) // 2
                stream.write(changed[:split])
                events.append(Event(clock(), str(path), "partial_write"))
                stream.write(changed[split:])
        else:
            path.write_bytes(changed)
        events.append(Event(clock(), str(path), "write"))
        if delay:
            sleep(delay)
        return path, events

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(operate, enumerate(paths)))
    changed_paths = [result[0] for result in results if result is not None]
    events = [event for result in results if result is not None for event in result[1]]
    state.write_text("\n".join(str(p.relative_to(directory)) for p in changed_paths), encoding="utf-8")
    return tuple(sorted(events, key=lambda event: event.at))


def restore(harness: Harness) -> None:
    directory = validate(harness)
    state = directory / STATE
    clean_paths = tuple((directory / "baseline").rglob("document-*.txt"))
    if len(clean_paths) != CORPUS_SIZE:
        raise ValueError("clean baseline incomplete")
    for clean in clean_paths:
        if _reparse(clean) or not clean.resolve().is_relative_to(directory):
            raise ValueError("unsafe baseline entry")
        path = directory / "corpus" / clean.parent.name / clean.name
        if _reparse(path) or not path.resolve().is_relative_to(directory):
            raise ValueError("unsafe corpus entry")
        path.write_bytes(clean.read_bytes())
    if state.exists():
        state.unlink()
