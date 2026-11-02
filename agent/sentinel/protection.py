"""What happens after a verdict: quarantine, event log. Shared by the watcher, CLI and native host."""

from __future__ import annotations

import logging
from typing import Any

from . import quarantine
from .config import Settings
from .db import Database
from .engine.verdict import CLEAN, MALICIOUS, Verdict

log = logging.getLogger(__name__)


def top_reason(v: Verdict) -> str:
    if not v.findings:
        return ""
    f = max(v.findings, key=lambda f: (f.severity, f.score))
    return f.detail


def act_on(db: Database, v: Verdict, settings: Settings, source: str) -> dict[str, Any]:
    """Record and (for malicious files) quarantine. Returns {label, quarantined, quarantine_id, error}."""
    out: dict[str, Any] = {"label": v.label, "quarantined": False, "quarantine_id": None, "error": None}
    if v.label == CLEAN or not v.path:
        return out
    data = v.to_dict()
    if v.label == MALICIOUS and settings.auto_quarantine:
        try:
            qid = quarantine.quarantine(db, v.path, data)
            out.update(quarantined=True, quarantine_id=qid)
            db.add_event(source, "threat", "Đã cách ly mối đe dọa",
                         f"{v.name}: {top_reason(v)}", {**data, "quarantine_id": qid})
        except quarantine.QuarantineError as e:
            out["error"] = str(e)
            db.add_event(source, "threat", "Phát hiện mối đe dọa (chưa cách ly được)",
                         f"{v.name}: {top_reason(v)} — {e}", data)
    elif v.label == MALICIOUS:
        db.add_event(source, "threat", "Phát hiện mối đe dọa", f"{v.name}: {top_reason(v)}", data)
    else:
        db.add_event(source, "warning", "Tệp đáng ngờ", f"{v.name}: {top_reason(v)} (điểm {v.score})", data)
    return out
