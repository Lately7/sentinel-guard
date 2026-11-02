"""Signature matching: known-bad hashes, user rule packs, optional YARA.

Detection content comes from public threat feeds (see feeds.py) and from rule
packs the user drops into the rules directory; the only built-in signature is
the industry-standard EICAR test file, so protection can be verified safely.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..db import Database
from .verdict import Finding, Severity

log = logging.getLogger(__name__)

# SHA-256 of the 68-byte EICAR anti-malware test file.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

_SEVERITY = {s.name.lower(): s for s in Severity}
_SCORE = {Severity.INFO: 0, Severity.LOW: 10, Severity.MEDIUM: 25, Severity.HIGH: 45, Severity.CRITICAL: 100}


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
    def __init__(self, db: Database, extra_rule_dirs: list[Path] | None = None) -> None:
        self.db = db
        dirs = [Path(__file__).resolve().parent.parent / "rules", config.user_rules_dir(), *(extra_rule_dirs or [])]
        self.pattern_rules = load_pattern_rules([d for d in dirs if d.is_dir()])
        self._yara = _load_yara([d for d in dirs if d.is_dir()])

    def match_hash(self, sha256: str) -> list[Finding]:
        if sha256 == EICAR_SHA256:
            return [Finding("signature", "eicar.test_file", Severity.CRITICAL, "EICAR anti-malware test file (harmless)", 100)]
        row = self.db.hash_info(sha256)
        if row:
            name = row["name"] or "known malware"
            return [Finding("signature", f"hash.{row['source']}", Severity.CRITICAL,
                            f"SHA-256 listed by {row['source']}: {name}", 100)]
        return []

    def match_content(self, data: bytes) -> list[Finding]:
        out: list[Finding] = []
        for r in self.pattern_rules:
            hits = [p in data for p in r.patterns]
            if (all(hits) if r.match_all else any(hits)):
                out.append(Finding("signature", r.id, r.severity, r.description, _SCORE[r.severity]))
        if self._yara is not None:
            try:
                for rule in self._yara.scan(data).matching_rules:
                    meta = dict(rule.metadata)
                    sev = _SEVERITY.get(str(meta.get("severity", "high")).lower(), Severity.HIGH)
                    out.append(Finding("yara", f"yara.{rule.identifier}", sev,
                                       str(meta.get("description", rule.identifier)), _SCORE[sev]))
            except Exception as e:  # a broken or slow rule must not abort the scan
                log.warning("yara match failed: %s", e)
        return out


def _load_yara(dirs: list[Path]):
    """User-supplied YARA rules (*.yar) via YARA-X, if installed."""
    try:
        import yara_x  # type: ignore[import-not-found]
    except ImportError:
        return None
    files = [p for d in dirs for p in sorted(d.glob("*.yar"))]
    if not files:
        return None
    compiler = yara_x.Compiler()
    loaded = 0
    for f in files:
        try:
            compiler.new_namespace(f.stem)
            compiler.add_source(f.read_text(encoding="utf-8", errors="replace"))
            loaded += 1
        except Exception as e:  # one bad file must not disable the others
            log.warning("skipping YARA file %s: %s", f, e)
    if not loaded:
        return None
    try:
        scanner = yara_x.Scanner(compiler.build())
        scanner.set_timeout(20)
        return scanner
    except Exception as e:
        log.warning("YARA rules failed to build: %s", e)
        return None
