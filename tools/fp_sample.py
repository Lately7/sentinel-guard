"""Read-only false-positive sample through the product's Gate v2.

Usage: python tools/fp_sample.py <max files> <root> [<root> ...]
Options: --engines core,json_rules,yara_x,clamav,defender,lnk,signer,motw --rules-dir COPY --seed N
COPY may hold rules/*.json, rules/*.yar, clamav/db/*.{cvd,cld}, and indicators/indicators-*.db.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import random
import shutil
import socket
import sys
import tempfile
import time
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from sentinel.engine.scanner import Scanner
    from sentinel.gate_v2.contract import FinalDecision

ENGINES = ("core", "json_rules", "yara_x", "clamav", "defender", "lnk", "signer", "motw")


def walk(roots: list[str], limit: int, seed: int = 0) -> Iterator[str]:
    rng = random.Random(seed)
    seen = 0
    for root in roots:
        for folder, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(folder, d))
                             and not os.path.isjunction(os.path.join(folder, d)))
            files.sort()
            rng.shuffle(dirs)
            rng.shuffle(files)
            for name in files:
                yield os.path.join(folder, name)
                seen += 1
                if seen >= limit:
                    return


def _engines(value: str) -> tuple[str, ...]:
    if value == "all":
        return ENGINES
    chosen = tuple(dict.fromkeys(part.strip() for part in value.split(",")))
    if "core" not in chosen or any(part not in ENGINES for part in chosen):
        raise argparse.ArgumentTypeError("phải có core; mã máy quét hợp lệ: " + ",".join(ENGINES))
    return tuple(engine for engine in ENGINES if engine in chosen)


def _protected(path: str | Path) -> bool:
    candidate = os.path.normcase(os.path.realpath(path))
    for name, fallback in (("ProgramData", r"C:\ProgramData"),
                           ("ProgramFiles", r"C:\Program Files")):
        base = os.path.normcase(os.path.realpath(Path(os.environ.get(name, fallback)) / "SentinelGuard"))
        try:
            if os.path.commonpath((candidate, base)) == base:
                return True
        except ValueError:
            pass
    return False


def _stage_rules(source: Path, home: Path) -> Path | None:
    # A disposable copy keeps the product's normal rule paths away from live state.
    rules = source / "rules" if (source / "rules").is_dir() else source
    if any(_protected(path) or path.is_symlink()
           for path in (rules, source / "clamav", source / "clamav" / "db", source / "indicators")):
        raise ValueError("bản sao luật không được dẫn tới trạng thái đã cài đặt")
    target = home / "rules"
    target.mkdir()
    for pattern in ("*.json", "*.yar"):
        for path in sorted(rules.glob(pattern)):
            if path.is_file() and not path.is_symlink():
                shutil.copyfile(path, target / path.name)
    clam_db = source / "clamav" / "db"
    if clam_db.is_dir():
        target = home / "clamav" / "db"
        target.mkdir(parents=True)
        for pattern in ("*.cvd", "*.cld"):
            for path in sorted(clam_db.glob(pattern)):
                if path.is_file() and not path.is_symlink():
                    shutil.copyfile(path, target / path.name)
    snapshots = sorted(path for path in (source / "indicators").glob("indicators-*.db")
                       if path.is_file() and not path.is_symlink())
    if snapshots:
        target = home / "indicators"
        target.mkdir()
        copied = target / snapshots[-1].name
        shutil.copyfile(snapshots[-1], copied)
        return copied
    return None


def _scan(scanner: Scanner, path: str, requested: tuple[str, ...]) -> FinalDecision:
    from sentinel import config
    from sentinel.engine.scanner import HEAD_BYTES
    from sentinel.gate_v2 import cache
    from sentinel.gate_v2.contract import CONTRACT_VERSION, EVIDENCE_POLICY_VERSION, LEGACY_POLICY_VERSION, ScanRequest
    from sentinel.gate_v2.orchestrator import scan
    from sentinel.gate_v2.policy import RequiredStages

    real = os.path.realpath(path)
    if _protected(real):
        raise PermissionError("thư mục SentinelGuard đã cài đặt")
    try:
        # A sample must not download a user's cloud library; the gate reports these itself.
        if getattr(os.stat(real), "st_file_attributes", 0) & 0x441000:
            head = b""
        else:
            with open(real, "rb") as stream:
                head = stream.read(HEAD_BYTES)
    except OSError:
        head = b""  # Gate v2 reports the failed measurement as unknown.
    plan = scanner._plan(os.path.basename(real), head, True)
    adapters = [adapter for adapter in plan.adapters if adapter.engine_id in requested]
    enabled = frozenset(adapter.engine_id for adapter in adapters)
    required = RequiredStages(plan.stages.required, plan.stages.required - enabled)
    disabled = tuple(engine for engine in ENGINES if engine not in requested)
    versions = tuple(item for item in plan.inputs.analyzer_versions if item[0] in requested)
    generation = cache.gate_generation(replace(plan.inputs, analyzer_versions=versions,
                                               disabled_by_policy=disabled))
    request = ScanRequest(CONTRACT_VERSION, uuid.uuid4().hex, "file", real, None, "cli",
                          "single_file", EVIDENCE_POLICY_VERSION, LEGACY_POLICY_VERSION,
                          time.monotonic_ns() + int(config.SCAN_DEADLINE_SECONDS * 1e9), None, False)
    return scan(request, adapters=adapters, stages=required, gate_generation=generation,
                auto_quarantine=False, max_bytes=config.MAX_SCAN_BYTES,
                resident_limit=config.MAX_DEEP_SCAN_BYTES)


def _upper_bound(hits: int, checked: int) -> float | None:
    if checked == 0:
        return None
    if hits == 0:
        return min(1.0, 3.0 / checked)  # one-sided approximate 95% rule of three
    z = 1.6448536269514722
    p = hits / checked
    z2 = z * z
    return min(1.0, (p + z2 / (2 * checked) + z * math.sqrt(
        p * (1 - p) / checked + z2 / (4 * checked**2))) / (1 + z2 / checked))


def _details(decision: FinalDecision) -> list[dict[str, str]]:
    details = [{"engine": result.engine_id, "rule": item.signature_id or item.detail_code}
               for result in decision.engine_results for item in result.evidence]
    details.extend({"engine": result.engine_id, "reason": result.readiness_code}
                   for result in decision.engine_results
                   if result.status.value not in ("completed", "partial"))
    if not details:
        details = [{"engine": "gate", "reason": code} for code in decision.reason_codes]
    return details


def _report(scanner: Scanner, roots: list[str], limit: int, seed: int,
            requested: tuple[str, ...]) -> dict[str, object]:
    from sentinel import indicators

    labels: collections.Counter[str] = collections.Counter()
    types: collections.Counter[str] = collections.Counter()
    stages: dict[str, collections.Counter[str]] = {engine: collections.Counter() for engine in requested}
    findings: list[dict[str, object]] = []
    generations: dict[str, set[str]] = collections.defaultdict(set)
    gate_generations: set[str] = set()
    began_at = datetime.now(timezone.utc).isoformat()
    began = time.monotonic()
    total_bytes = 0
    for path in walk(roots, limit, seed):
        types[Path(path).suffix.lower() or "[no extension]"] += 1
        try:
            decision = _scan(scanner, path, requested)
        except Exception as exc:
            labels["unknown"] += 1
            findings.append({"path": path, "verdict": "unknown",
                             "details": [{"engine": "gate", "reason": type(exc).__name__}]})
            for engine in requested:
                stages[engine]["not_run"] += 1
            continue
        present = {result.engine_id: result for result in decision.engine_results}
        incomplete_file = [engine for engine in requested
                           if engine not in present or present[engine].status.value != "completed"]
        label = "unknown" if decision.verdict.value == "clean" and incomplete_file else decision.verdict.value
        labels[label] += 1
        gate_generations.add(decision.gate_generation)
        total_bytes += decision.identity.size if decision.identity else 0
        for engine in requested:
            result = present.get(engine)
            stages[engine][result.status.value if result else "not_run"] += 1
            if result and result.generation_digest:
                generations[engine].add(result.generation_digest)
        if label != "clean":
            details = _details(decision)
            details.extend({"engine": engine, "reason": "NOT_COMPLETED"} for engine in incomplete_file)
            findings.append({"path": path, "verdict": label, "details": details})
    elapsed = time.monotonic() - began
    sampled = sum(labels.values())
    checked = labels["clean"] + labels["suspicious"] + labels["malicious"]
    hits = labels["suspicious"] + labels["malicious"]
    coverage = {engine: {"ran": counts["completed"] + counts["partial"] > 0,
                         "statuses": dict(counts)} for engine, counts in stages.items()}
    incomplete = [engine for engine, counts in stages.items()
                  if counts["completed"] != sampled]
    json_rules, yara_rules = scanner._rule_adapters()
    configured_rules = {"json_rules": json_rules.ruleset_digest,
                        "yara_x": yara_rules.ruleset_digest}
    snapshot = scanner.db.get_meta(indicators.POINTER_KEY, None)
    snapshot_digest = None
    if snapshot and scanner.db.indicators._current() is not None and Path(snapshot).is_file():
        with open(snapshot, "rb") as stream:
            snapshot_digest = hashlib.file_digest(stream, "sha256").hexdigest()
    missing = [engine for engine in ENGINES if engine not in requested]
    limits = (["không có tệp"] if not sampled else []) + (["không có snapshot"] if not snapshot_digest else [])
    limits += ["không yêu cầu: " + ",".join(missing)] if missing else []
    limits += ["chưa chạy đủ: " + ",".join(incomplete)] if incomplete else []
    return {
        "scope": "Tỷ lệ chưa đầy đủ: " + "; ".join(limits) if limits else "Đủ bộ máy quét của sản phẩm",
        "requested_engines": list(requested), "engine_coverage": coverage,
        "time_utc": began_at, "seed": seed,
        "snapshot_generation": snapshot_digest or "không có (thư mục tạm)",
        "db_generation": scanner.db.generation(), "gate_generations": sorted(gate_generations),
        "configured_rule_generations": configured_rules,
        "rule_generations": {engine: sorted(values) for engine, values in generations.items()},
        "files_sampled": sampled, "by_file_type": dict(types), "verdict_counts": dict(labels),
        "seconds": round(elapsed, 3), "mb": round(total_bytes / 1e6, 3),
        "files_per_second": round(sampled / elapsed, 2) if elapsed else None,
        "rate": {"false_positives": hits, "checked": checked,
                 "estimate": hits / checked if checked else None,
                 "upper_95": _upper_bound(hits, checked),
                 "method": "quy tắc ba" if checked and hits == 0 else "Wilson một phía" if checked else "không có tệp đã kiểm tra"},
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("limit", type=int)
    parser.add_argument("roots", nargs="+")
    parser.add_argument("--engines", type=_engines, default=ENGINES)
    parser.add_argument("--rules-dir", type=Path)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    if args.limit < 1:
        parser.error("số tệp phải lớn hơn 0")
    if args.rules_dir is not None and not args.rules_dir.is_dir():
        parser.error("--rules-dir phải là thư mục có sẵn")
    if any(_protected(path) for path in (*args.roots, *((args.rules_dir,) if args.rules_dir else ()))):
        parser.error("không thể lấy mẫu từ thư mục SentinelGuard đã cài đặt")
    agent_path = str(Path(__file__).resolve().parents[1] / "agent")
    sys.path.insert(0, agent_path)
    from sentinel.db import Database
    from sentinel.engine.scanner import Scanner

    prior_home = os.environ.get("SENTINEL_HOME")
    prior_port = os.environ.get("SENTINEL_CLAMD_PORT")
    try:
        with tempfile.TemporaryDirectory(prefix="sg-fp-") as directory:
            os.environ["SENTINEL_HOME"] = directory
            snapshot = _stage_rules(args.rules_dir, Path(directory)) if args.rules_dir is not None else None
            # The sampler must not connect to the installed service's clamd port.
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                os.environ["SENTINEL_CLAMD_PORT"] = str(reservation.getsockname()[1])
            db = Database()
            try:
                if snapshot is not None:
                    from sentinel import indicators
                    db.set_meta(indicators.POINTER_KEY, str(snapshot))
                    db.bump_generation()
                scanner = Scanner(db, use_defender="defender" in args.engines,
                                  use_clamav="clamav" in args.engines)
                try:
                    if scanner.clamav is not None:
                        scanner.clamav.start()
                    report = _report(scanner, args.roots, args.limit, args.seed, args.engines)
                finally:
                    if scanner.clamav is not None:
                        scanner.clamav.stop()
                print(json.dumps(report, indent=2, ensure_ascii=False))
            finally:
                db.close()
    finally:
        sys.path.remove(agent_path)
        if prior_home is None:
            os.environ.pop("SENTINEL_HOME", None)
        else:
            os.environ["SENTINEL_HOME"] = prior_home
        if prior_port is None:
            os.environ.pop("SENTINEL_CLAMD_PORT", None)
        else:
            os.environ["SENTINEL_CLAMD_PORT"] = prior_port
    return 0


if __name__ == "__main__":
    sys.exit(main())
