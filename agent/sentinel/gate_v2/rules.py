"""Preloaded JSON packs and YARA-X sources for the restricted content worker."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import archive
from .content import BoundReader, ContentError
from .contract import (CONTRACT_VERSION, ByteRange, CancellationToken, Category,
                       EngineResult, Evidence, FileIdentity, ScanError, ScanRequest,
                       StageStatus, Strength, VerdictCode)
from .coverage import CoverageLedger, normalize_ranges
from .evidence import select_evidence


# Past the resident limit rules still see the end, where appended payloads sit.
TAIL_BYTES = 8 * 1024 * 1024


def _tail(reader: BoundReader, measured: FileIdentity, cancel: CancellationToken) -> tuple[int, bytes]:
    if measured.size <= reader.resident_limit:
        return 0, b""
    length = min(TAIL_BYTES, measured.size - reader.resident_limit, reader.resident_limit)
    return measured.size - length, reader.read(measured.size - length, length, cancel)


@dataclass(frozen=True)
class SourceRecord:
    name: str
    digest: str
    accepted: bool
    reason: str
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Pattern:
    name: str
    digest: str
    user: bool
    rule_id: str
    critical: bool
    patterns: tuple[bytes, ...]
    all_patterns: bool


def _result(engine: str, request: ScanRequest, measured: FileIdentity, reader: BoundReader,
            start: int, evidence: list[Evidence], status: StageStatus, readiness: str,
            generation: str, *, error: ScanError | None = None,
            limits: tuple[str, ...] = (), ledger: CoverageLedger | None = None) -> EngineResult:
    ledger = ledger or CoverageLedger(measured.size, certainty="verified")
    ledger.inspected = reader.ranges
    for code in limits:
        ledger.limit(code)
    if reader.ranges != ((ByteRange(0, measured.size),) if measured.size else ()):
        ledger.fixed_reduction = status is StageStatus.PARTIAL and not limits
    retained = select_evidence(evidence, ledger)
    coverage = ledger.finish()
    if coverage.mode == "runtime_partial" and status is StageStatus.COMPLETED:
        status = StageStatus.PARTIAL
    verdict = (VerdictCode.MALICIOUS if any(e.strength is Strength.CONCLUSIVE for e in retained)
               else VerdictCode.SUSPICIOUS if retained else
               VerdictCode.CLEAN if status is StageStatus.COMPLETED else VerdictCode.UNKNOWN)
    return EngineResult(CONTRACT_VERSION, engine, request.file_id, measured, status,
                        verdict, coverage, retained, None, None, generation,
                        readiness, start, (time.monotonic_ns() - start) // 1_000_000, error)


def _parse_pack(name: str, raw: bytes, user: bool) -> tuple[list[_Pattern], SourceRecord]:
    digest = hashlib.sha256(raw).hexdigest()
    try:
        document = json.loads(raw.decode("utf-8", errors="strict"))
        if type(document) is not dict or set(document) != {"rules"} or type(document["rules"]) is not list:
            raise ValueError("PACK_SCHEMA")
        rules: list[_Pattern] = []
        seen: set[str] = set()
        for item in document["rules"]:
            if type(item) is not dict or not {"id", "severity"} <= set(item) or set(item) - {"id", "severity", "description", "text", "hex", "condition"}:
                raise ValueError("RULE_SCHEMA")
            rid, severity = item["id"], item["severity"]
            if type(rid) is not str or not rid or len(rid) > 128 or rid in seen:
                raise ValueError("RULE_ID")
            seen.add(rid)
            if severity not in ("info", "low", "medium", "high", "critical") or type(severity) is not str:
                raise ValueError("SEVERITY")
            if type(item.get("description", "")) is not str or len(item.get("description", "")) > 512:
                raise ValueError("DESCRIPTION")
            condition = item.get("condition", "any")
            if condition not in ("any", "all"):
                raise ValueError("CONDITION")
            texts, hexes = item.get("text", []), item.get("hex", [])
            if type(texts) is not list or type(hexes) is not list:
                raise ValueError("PATTERNS")
            if len(texts) + len(hexes) > 64:
                raise ValueError("PATTERN_LIMIT")
            patterns: list[bytes] = []
            for text in texts:
                if type(text) is not str:
                    raise ValueError("PATTERN_TEXT")
                patterns.append(text.encode("utf-8"))
            for value in hexes:
                if type(value) is not str:
                    raise ValueError("PATTERN_HEX")
                try:
                    patterns.append(bytes.fromhex(value))
                except ValueError as exc:
                    raise ValueError("PATTERN_HEX") from exc
            if not patterns or any(not 4 <= len(p) <= 4096 for p in patterns):
                raise ValueError("PATTERN_SIZE")
            rules.append(_Pattern(name, digest, user, rid, severity == "critical", tuple(patterns), condition == "all"))
        if not rules:
            raise ValueError("EMPTY_PACK")
        return rules, SourceRecord(name, digest, True, "OK", tuple(r.rule_id for r in rules[:64]))
    except (UnicodeError, ValueError, TypeError, KeyError) as exc:
        code = str(exc) if isinstance(exc, ValueError) and str(exc).isupper() else "INVALID_JSON"
        return [], SourceRecord(name, digest, False, code)


class JsonRulesAdapter:
    engine_id = "json_rules"
    reopens_path = False

    def __init__(self, packs: tuple[tuple[str, bytes, bool], ...]) -> None:
        self.rules: list[_Pattern] = []
        records: list[SourceRecord] = []
        for name, raw, user in packs:
            parsed, record = _parse_pack(name, raw, user)
            self.rules.extend(parsed)
            records.append(record)
        self.manifest = tuple(records)
        self.ruleset_digest = hashlib.sha256(json.dumps(
            [(r.name, r.digest, r.accepted, r.reason) for r in records], separators=(",", ":")
        ).encode()).hexdigest()

    @classmethod
    def from_directories(cls, user_dir: Path, bundled_dirs: tuple[Path, ...] = ()) -> JsonRulesAdapter:
        packs: list[tuple[str, bytes, bool]] = []
        for directory, user in ((d, False) for d in bundled_dirs):
            for path in sorted(directory.glob("*.json")):
                try:
                    packs.append((str(path), path.read_bytes(), user))
                except OSError:
                    packs.append((str(path), b"", user))
        for path in sorted(user_dir.glob("*.json")):
            try:
                packs.append((str(path), path.read_bytes(), True))
            except OSError:
                packs.append((str(path), b"", True))
        return cls(tuple(packs))

    def readiness(self) -> str:
        if not self.rules:
            return "RULES_UNAVAILABLE"
        return "RULES_DEGRADED" if any(not r.accepted for r in self.manifest) else "READY"

    def scan_bound(self, request: ScanRequest, measured: FileIdentity,
                   cancel: CancellationToken, reader: BoundReader) -> EngineResult:
        start = time.monotonic_ns()
        state = self.readiness()
        if not self.rules:
            return _result(self.engine_id, request, measured, reader, start, [],
                           StageStatus.UNAVAILABLE, state, self.ruleset_digest)
        evidence: list[Evidence] = []
        ledger = CoverageLedger(measured.size, certainty="verified")
        try:
            body = reader.read(0, min(measured.size, reader.resident_limit), cancel)
            def inspect(payload: bytes, member_path: str | None = None, base: int = 0) -> None:
                for rule in self.rules:
                    matches = [payload.find(p) for p in rule.patterns]
                    if (all(i >= 0 for i in matches) if rule.all_patterns else any(i >= 0 for i in matches)):
                        position = next(i for i in matches if i >= 0)
                        length = len(rule.patterns[matches.index(position)])
                        spans = reader.ranges[:1] if member_path else (ByteRange(base + position, base + position + length),)
                        evidence.append(Evidence(f"json.{rule.digest[:12]}.{rule.rule_id}"[:128],
                                                 self.engine_id, rule.rule_id, None, Category.MALWARE,
                                                 Strength.CONCLUSIVE if rule.user and rule.critical else Strength.SUPPORTING,
                                                 "member" if member_path else "outer", member_path, spans,
                                                 rule.name[:128], rule.digest, None, True, "JSON_RULE"))
            inspect(body)
            start_of_tail, tail = _tail(reader, measured, cancel)
            if tail:
                inspect(tail, base=start_of_tail)
            if archive.is_zip(body):
                if len(body) == measured.size:
                    stopped = archive.walk(body, ledger, cancel, lambda path, payload: inspect(payload, path),
                                           request.deadline_monotonic_ns)
                    if stopped == "DEADLINE":
                        return _result(self.engine_id, request, measured, reader, start, evidence,
                                       StageStatus.TIMEOUT, state, self.ruleset_digest,
                                       error=ScanError("DEADLINE", "archive", "DEADLINE", True), ledger=ledger)
                    if stopped == "CANCELLED":
                        return _result(self.engine_id, request, measured, reader, start, evidence,
                                       StageStatus.CANCELLED, state, self.ruleset_digest, ledger=ledger)
                else:
                    ledger.parser("zip", "partial")
            status = StageStatus.PARTIAL if state == "RULES_DEGRADED" or len(body) < measured.size else StageStatus.COMPLETED
            return _result(self.engine_id, request, measured, reader, start, evidence,
                           status, state, self.ruleset_digest,
                           limits=("RULES_DEGRADED",) if state == "RULES_DEGRADED" else (), ledger=ledger)
        except ContentError as exc:
            status = StageStatus.CHANGED if exc.code == "CHANGED" else StageStatus.CANCELLED if exc.code == "CANCELLED" else StageStatus.ERROR
            return _result(self.engine_id, request, measured, reader, start, evidence, status,
                           exc.code, self.ruleset_digest, error=ScanError(exc.code, "read", exc.code, True), ledger=ledger)


class YaraXAdapter:
    engine_id = "yara_x"
    reopens_path = False

    def __init__(self, sources: tuple[tuple[str, str, str], ...], *, timeout: int = 20,
                 max_matches_per_pattern: int = 1024) -> None:
        self.timeout = timeout
        self.match_cap = max_matches_per_pattern
        self._rules = None
        self.manifest: tuple[SourceRecord, ...]
        self.ruleset_digest = hashlib.sha256(json.dumps(sources, separators=(",", ":")).encode()).hexdigest()
        try:
            import yara_x
        except ImportError:
            self._yara = None
            self.manifest = tuple(SourceRecord(name, hashlib.sha256(src.encode()).hexdigest(), False, "YARA_UNAVAILABLE")
                                  for _, name, src in sources)
            return
        self._yara = yara_x
        compiler = yara_x.Compiler(includes_enabled=False)
        records: list[SourceRecord] = []
        for namespace, name, source in sources:
            digest = hashlib.sha256(source.encode()).hexdigest()
            try:
                compiler.new_namespace(namespace)
                compiler.add_source(source, origin=name)
                records.append(SourceRecord(name, digest, True, "OK"))
            except Exception as exc:
                records.append(SourceRecord(name, digest, False, "COMPILE_ERROR", (str(exc)[:128],)))
        diagnostics = tuple(str(item)[:128] for item in
                            (*compiler.warnings(), *compiler.errors(), *compiler.ignored_rules()))
        self.manifest = tuple(records) + (SourceRecord("diagnostics", self.ruleset_digest, True, "DIAGNOSTICS", diagnostics[:64]),)
        try:
            self._rules = compiler.build()
        except Exception:
            self._rules = None

    def readiness(self) -> str:
        if self._rules is None:
            return "YARA_UNAVAILABLE"
        return "RULES_DEGRADED" if any(not r.accepted for r in self.manifest) else "READY"

    def _scanner(self) -> Any:
        scanner = self._yara.Scanner(self._rules)
        scanner.set_timeout(self.timeout)
        scanner.max_matches_per_pattern(self.match_cap)
        return scanner

    def scan_bound(self, request: ScanRequest, measured: FileIdentity,
                   cancel: CancellationToken, reader: BoundReader) -> EngineResult:
        start = time.monotonic_ns()
        state = self.readiness()
        if self._rules is None:
            return _result(self.engine_id, request, measured, reader, start, [],
                           StageStatus.UNAVAILABLE, state, self.ruleset_digest)
        evidence: list[Evidence] = []
        ledger = CoverageLedger(measured.size, certainty="verified")
        try:
            if measured.size > reader.resident_limit:
                body = reader.read(0, reader.resident_limit, cancel)
                partial = True
            else:
                body = reader.read(0, measured.size, cancel)
                partial = False
            def inspect(payload: bytes, member_path: str | None = None, base: int = 0) -> None:
                scanner = self._scanner()
                try:
                    matches = scanner.scan(payload).matching_rules
                    for rule in matches:
                        offsets = [(match.offset, match.length) for pattern in rule.patterns
                                   for match in pattern.matches][:64]
                        # A rule of pure conditions (a private helper) has no offsets;
                        # it then points at what was scanned.
                        # Patterns match out of order and can overlap; evidence
                        # ranges must not, or the contract refuses the whole hit.
                        spans = (reader.ranges[:1] if member_path else normalize_ranges(tuple(
                            ByteRange(base + offset, base + offset + length)
                            for offset, length in offsets if length > 0), measured.size) or reader.ranges[:1])
                        evidence.append(Evidence(f"yara.{rule.namespace}.{rule.identifier}"[:128], self.engine_id,
                                                 rule.identifier[:128], f"{rule.namespace}.{rule.identifier}"[:512],
                                                 Category.MALWARE, Strength.SUPPORTING,
                                                 "member" if member_path else "outer", member_path,
                                                 spans, rule.namespace[:128], self.ruleset_digest,
                                                 None, True, "YARA_MATCH"))
                finally:
                    del scanner
            inspect(body)
            start_of_tail, tail = _tail(reader, measured, cancel)
            if tail:
                inspect(tail, base=start_of_tail)
            if archive.is_zip(body):
                if not partial:
                    stopped = archive.walk(body, ledger, cancel, lambda path, payload: inspect(payload, path),
                                           request.deadline_monotonic_ns)
                    if stopped == "DEADLINE":
                        return _result(self.engine_id, request, measured, reader, start, evidence,
                                       StageStatus.TIMEOUT, state, self.ruleset_digest,
                                       error=ScanError("DEADLINE", "archive", "DEADLINE", True), ledger=ledger)
                    if stopped == "CANCELLED":
                        return _result(self.engine_id, request, measured, reader, start, evidence,
                                       StageStatus.CANCELLED, state, self.ruleset_digest, ledger=ledger)
                else:
                    ledger.parser("zip", "partial")
            status = StageStatus.PARTIAL if partial or state == "RULES_DEGRADED" else StageStatus.COMPLETED
            return _result(self.engine_id, request, measured, reader, start, evidence, status,
                           state, self.ruleset_digest,
                           limits=("RULES_DEGRADED",) if state == "RULES_DEGRADED" else (), ledger=ledger)
        except ContentError as exc:
            status = StageStatus.CHANGED if exc.code == "CHANGED" else StageStatus.CANCELLED if exc.code == "CANCELLED" else StageStatus.ERROR
            code = exc.code
        except self._yara.TimeoutError:
            status, code = StageStatus.TIMEOUT, "YARA_TIMEOUT"
        except Exception:
            status, code = StageStatus.ERROR, "YARA_SCAN_ERROR"
        return _result(self.engine_id, request, measured, reader, start, evidence, status,
                       code, self.ruleset_digest, error=ScanError(code, "scan", code, True), ledger=ledger)
