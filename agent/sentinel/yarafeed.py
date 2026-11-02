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
import zipfile

from . import config
from .feeds import _fetch_bytes

log = logging.getLogger(__name__)

URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
TARGET = "yara-forge-core.yar"
MAX_RULES_BYTES = 64 * 1024 * 1024

# A rule starts at a line beginning with optional modifiers + "rule NAME".
_RULE_START = re.compile(r"^(?:(?:private|global)\s+)*rule\s+\w+", re.MULTILINE)


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


def update(fetch=_fetch_bytes) -> str:
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
    tmp = dest.with_suffix(".yar.tmp")
    tmp.write_text(good, encoding="utf-8")
    os.replace(tmp, dest)  # a half-written file must never be loaded
    return f"ok: {kept} rules" + (f", {dropped} not supported by YARA-X" if dropped else "")
