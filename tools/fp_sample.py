"""Read-only sample over legitimate software: labels, reasons, speed.

Uses a disposable SENTINEL_HOME and never quarantines: it only calls Scanner.
Usage: python tools/fp_sample.py <max files> <root> [<root> ...]
"""

from __future__ import annotations

import collections
import json
import os
import sys
import tempfile
import time
from pathlib import Path


def walk(roots: list[str], limit: int):
    seen = 0
    for root in roots:
        for folder, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(folder, d))
                       and not os.path.isjunction(os.path.join(folder, d))]
            for name in files:
                yield os.path.join(folder, name)
                seen += 1
                if seen >= limit:
                    return


def main() -> int:
    limit, roots = int(sys.argv[1]), sys.argv[2:]
    os.environ["SENTINEL_HOME"] = tempfile.mkdtemp(prefix="sg-fp-")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
    from sentinel.db import Database
    from sentinel.engine.scanner import Scanner

    db = Database()
    scanner = Scanner(db, use_defender=False, use_clamav=False)
    labels: collections.Counter[str] = collections.Counter()
    reasons: collections.Counter[str] = collections.Counter()
    samples: dict[str, list[str]] = collections.defaultdict(list)
    began = time.monotonic()
    slowest = (0.0, "")
    total = 0
    for path in walk(roots, limit):
        start = time.monotonic()
        try:
            verdict = scanner.scan_file(path, use_cache=False)
        except BaseException as exc:  # the point of this tool is to see these
            labels["CRASH"] += 1
            samples["CRASH"].append(f"{type(exc).__name__}: {path}")
            continue
        slowest = max(slowest, (time.monotonic() - start, path))
        total += verdict.size
        labels[verdict.label] += 1
        decision = verdict.decision
        for code in (decision.reason_codes if decision else ()):
            if verdict.label != "clean":
                reasons[code] += 1
        if verdict.label != "clean":
            for result in (decision.engine_results if decision else ()):
                for code in (*result.coverage.object_reasons, *result.coverage.limits_hit):
                    reasons[f"{result.engine_id}:{code}"] += 1
                if verdict.label == "suspicious":
                    for item in result.evidence:
                        reasons[f"evidence:{item.detail_code}"] += 1
            if len(samples[verdict.label]) < 12:
                samples[verdict.label].append(path)
    elapsed = time.monotonic() - began
    print(json.dumps({"labels": labels, "seconds": round(elapsed, 1), "mb": round(total / 1e6),
                      "files_per_second": round(sum(labels.values()) / elapsed, 1),
                      "slowest": [round(slowest[0], 2), slowest[1]],
                      "reasons": reasons.most_common(25), "samples": samples}, indent=1, ensure_ascii=False))
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
