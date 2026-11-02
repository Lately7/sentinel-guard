"""Signature matching: known-bad hashes, user rule packs, optional YARA.

Detection content comes from public threat feeds (see feeds.py) and from rule
packs the user drops into the rules directory; the only built-in signature is
the industry-standard EICAR test file, so protection can be verified safely.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..db import Database
from .verdict import Severity

log = logging.getLogger(__name__)

# SHA-256 of the 68-byte EICAR anti-malware test file.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

_SEVERITY = {s.name.lower(): s for s in Severity}
_RULE = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+\w+", re.M)


@dataclass(frozen=True)
class PatternRule:
    id: str
    severity: Severity
    description: str
    patterns: tuple[bytes, ...]
    match_all: bool


def load_pattern_rules(dirs: list[Path]) -> list[PatternRule]:
    """Load `*.json` rule packs: {"rules": [{"id", "severity", "description", "text"|"hex": [...], "condition": "any"|"all"}]}."""
    rules: list[PatternRule] = []
    for d in dirs:
        for f in sorted(d.glob("*.json")):
            try:
                pack = json.loads(f.read_text(encoding="utf-8"))
                for r in pack.get("rules", []):
                    pats = [p.encode("utf-8") for p in r.get("text", [])]
                    pats += [bytes.fromhex(p) for p in r.get("hex", [])]
                    pats = [p for p in pats if len(p) >= 4]  # tiny patterns only produce false positives
                    if not pats or not r.get("id"):
                        continue
                    rules.append(PatternRule(
                        id=str(r["id"]),
                        severity=_SEVERITY.get(str(r.get("severity", "high")).lower(), Severity.HIGH),
                        description=str(r.get("description", r["id"])),
                        patterns=tuple(pats),
                        match_all=r.get("condition", "any") == "all",
                    ))
            except (OSError, ValueError, TypeError, AttributeError) as e:
                log.warning("skipping rule pack %s: %s", f, e)
    return rules


class SignatureEngine:
    """What rules are installed, for the dashboard and for Gate v2's adapters, which
    do the matching. It compiles nothing: 5,000 YARA rules take seconds."""

    def __init__(self, db: Database, extra_rule_dirs: list[Path] | None = None) -> None:
        self.db = db
        self.bundled_dirs = [d for d in (Path(__file__).resolve().parent.parent / "rules", *(extra_rule_dirs or []))
                             if d.is_dir()]
        self._dirs = [*self.bundled_dirs, config.user_rules_dir()]
        self.pattern_rules = load_pattern_rules(self._dirs)
        self.yara_rules = sum(len(_RULE.findall(source)) for _, _, source in self.yara_sources())

    def yara_sources(self) -> tuple[tuple[str, str, str], ...]:
        """(namespace, origin, source) of every *.yar file."""
        out = []
        for d in self._dirs:
            for f in sorted(d.glob("*.yar")):
                try:
                    out.append((f.stem, str(f), f.read_text(encoding="utf-8", errors="replace")))
                except OSError as e:
                    log.warning("skipping YARA file %s: %s", f, e)
        return tuple(out)


def _yara_severity(meta: dict) -> Severity:
    if "severity" in meta:
        return _SEVERITY.get(str(meta["severity"]).lower(), Severity.HIGH)
    # YARA Forge rates every rule 0-100 by how specific it is. Only the most
    # specific reach HIGH, so one generic match never quarantines a file.
    score = meta.get("score")
    if isinstance(score, int) and not isinstance(score, bool):
        if score >= 80:
            return Severity.HIGH
        if score >= 60:
            return Severity.MEDIUM
        return Severity.LOW
    return Severity.HIGH
