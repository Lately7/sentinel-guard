"""Open-source YARA rules for the YARA-X layer: the YARA Forge "core" package.

YARA Forge collects and quality-filters public rule repositories (Neo23x0
signature-base, Elastic, ReversingLabs, …); "core" is its high-accuracy,
low-false-positive set. Rules that YARA-X cannot compile are dropped one by
one rather than losing the whole package.
"""

from __future__ import annotations

import importlib.util
import io
import logging
import os
import re
import time
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from . import config
from .feeds import _fetch_bytes

log = logging.getLogger(__name__)

URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
TARGET = "yara-forge-core.yar"
MAX_RULES_BYTES = 64 * 1024 * 1024

# A rule starts at a line beginning with optional modifiers + "rule NAME".
_RULE_START = re.compile(r"^(?:(?:private|global)\s+)*rule\s+\w+", re.MULTILINE)


class TrialSession(Protocol):
    def call(self, op: str, args: dict, *, deadline_ns: int) -> dict: ...
    def close(self) -> None: ...


def _trial_sources(candidate: str, dest: Path, bundled: Path,
                   user: Path) -> tuple[tuple[str, str, str], ...]:
    sources: list[tuple[str, str, str]] = []
    for directory in (bundled, user):
        paths = set(directory.glob("*.yar"))
        if directory == user:
            paths.add(dest)
        for path in sorted(paths):
            source = candidate if path == dest else path.read_text(encoding="utf-8", errors="replace")
            sources.append((path.stem, str(path), source))
    return tuple(sources)


def _trial_worker(candidate: str, dest: Path, session_factory: Callable[..., TrialSession]) -> None:
    from .gate_v2.contract import (CONTRACT_VERSION, EVIDENCE_POLICY_VERSION,
                                   EngineResult, FileIdentity, ScanRequest, StageStatus)
    from .gate_v2.rules import JsonRulesAdapter

    bundled = Path(__file__).resolve().parent / "rules"
    user = dest.parent
    packs = JsonRulesAdapter.from_directories(user, (bundled,) if bundled.is_dir() else ())
    sources = _trial_sources(candidate, dest, bundled, user)
    session = session_factory(json_packs=packs.sources, yara_sources=sources)
    try:
        payload = b""
        identity = FileIdentity(None, None, None, 0,
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", None, None)
        deadline = time.monotonic_ns() + 60_000_000_000
        request = ScanRequest(CONTRACT_VERSION, "rules-trial", "rules-trial", None, payload,
                              "test", "memory", EVIDENCE_POLICY_VERSION, EVIDENCE_POLICY_VERSION,
                              deadline, None, False)
        reply = session.call("scan", {"engine": "yara_x", "request": request.to_dict(),
                                      "identity": identity.to_dict()}, deadline_ns=deadline)
        result = EngineResult.from_dict(reply["engine_result"])
        if (result.engine_id != "yara_x" or result.file_id != request.file_id or
                result.status is not StageStatus.COMPLETED or result.identity != identity or
                result.readiness_code != "READY"):
            raise ValueError("worker did not load all rules")
    finally:
        session.close()


def split_rules(source: str) -> tuple[str, list[str]]:
    """(preamble with imports, [rule sources]). Comments between rules stay attached to the previous rule."""
    starts = [m.start() for m in _RULE_START.finditer(source)]
    if not starts:
        return source, []
    pre = source[: starts[0]]
    rules = [source[a:b] for a, b in zip(starts, starts[1:] + [len(source)])]
    return pre, rules


def compile_filtered(source: str) -> tuple[str, int, int]:
    """Returns (source that compiles, rules kept, rules dropped)."""
    import yara_x  # type: ignore[import-not-found]

    try:
        c = yara_x.Compiler()
        c.add_source(source)
        c.build()
        return source, len(split_rules(source)[1]), 0
    except Exception:
        pass
    pre, rules = split_rules(source)
    imports = "".join(line + "\n" for line in pre.splitlines() if line.strip().startswith("import "))
    kept: list[str] = []
    dropped = 0
    for r in rules:
        c = yara_x.Compiler()
        try:
            # Each rule is checked with the rules kept so far: a rule may
            # reference an earlier (private) one by name.
            c.add_source(imports + "".join(kept) + r)
            kept.append(r)
        except Exception:
            dropped += 1
    return imports + "".join(kept), len(kept), dropped


def update(fetch=_fetch_bytes, session_factory: Callable[..., TrialSession] | None = None) -> str:
    if importlib.util.find_spec("yara_x") is None:
        return "error: yara-x is not installed (pip install yara-x)"
    try:
        raw = fetch(URL)
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            members = [i for i in zf.infolist() if i.filename.endswith(".yar")]
            if not members:
                return "error: no .yar file in the YARA Forge package"
            info = max(members, key=lambda i: i.file_size)
            if info.file_size > MAX_RULES_BYTES:
                return "error: rule file too large"
            with zf.open(info) as fh:
                source = fh.read(MAX_RULES_BYTES + 1).decode("utf-8", errors="replace")
    except (OSError, ValueError, zipfile.BadZipFile) as e:
        return f"error: {e}"
    good, kept, dropped = compile_filtered(source)
    if not kept:
        return "error: no rule compiled"
    dest = config.user_rules_dir() / TARGET
    if session_factory is None:
        from .service.paths import active_version
        from .service.workerclient import WorkerSession

        # Only the service's worker has a memory cap to die against: a portable
        # scan runs in this process, where the compile above already proved the rules.
        session_factory = WorkerSession if active_version() is not None else None
    if session_factory is not None:
        try:
            _trial_worker(good, dest, session_factory)
        except Exception as e:
            log.warning("rule update refused by the worker trial: %s", e)
            return "error: rule worker trial failed"
    tmp = dest.with_suffix(".yar.tmp")
    try:
        tmp.write_text(good, encoding="utf-8")
        os.replace(tmp, dest)  # a half-written file must never be loaded
    except OSError:
        tmp.unlink(missing_ok=True)
        return "error: could not install rule file"
    return f"ok: {kept} rules" + (f", {dropped} not supported by YARA-X" if dropped else "")
