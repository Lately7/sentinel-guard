"""What happens after a verdict: quarantine, event log. Shared by the watcher, CLI and native host."""

from __future__ import annotations

import logging
from typing import Any

from . import quarantine
from .config import Settings
from .db import Database
from .engine.verdict import CLEAN, MALICIOUS, Verdict
from .gate_v2.contract import ActionCode
from .gate_v2.legacy import UNKNOWN

log = logging.getLogger(__name__)


def top_reason(v: Verdict) -> str:
    if not v.findings:
        return ""
    f = max(v.findings, key=lambda f: (f.severity, f.score))
    return f.detail


def _wants_quarantine(v: Verdict) -> bool:
    # The label says what is known, the action says what to do, and they differ:
    # legacy-v0 still quarantines weak ClamAV names, a file that changed is left
    # alone. A finding added after the scan has no action behind it.
    action = getattr(getattr(v, "decision", None), "action_decision", None)
    if action is None or getattr(v, "escalated", False):
        return v.label == MALICIOUS
    return action.action is ActionCode.QUARANTINE


def _unaccepted(v: Verdict) -> bool:
    decision = getattr(v, "decision", None)
    return decision is not None and "UNACCEPTED_DETECTION" in decision.reason_codes


def act_on(db: Database, v: Verdict, settings: Settings, source: str) -> dict[str, Any]:
    """Record and (for malicious files) quarantine. Returns {label, quarantined, quarantine_id, error}."""
    out: dict[str, Any] = {"label": v.label, "quarantined": False, "quarantine_id": None, "error": None}
    if v.label == CLEAN or not v.path:
        return out
    data = v.to_dict()
    if v.label == UNKNOWN:
        # Not checked is not an event per file; an engine that spoke but could not
        # be believed is, because someone should look at that file.
        if _unaccepted(v):
            db.add_event(source, "warning", "Có tín hiệu nhưng chưa xác nhận được",
                         f"{v.name}: {top_reason(v)}", data)
        return out
    wanted = _wants_quarantine(v)
    if wanted and settings.auto_quarantine:
        try:
            qid = quarantine.quarantine(db, v.path, data)
            out.update(quarantined=True, quarantine_id=qid)
            db.add_event(source, "threat", "Đã cách ly mối đe dọa",
                         f"{v.name}: {top_reason(v)}", {**data, "quarantine_id": qid})
        except quarantine.QuarantineError as e:
            out["error"] = str(e)
            db.add_event(source, "threat", "Phát hiện mối đe dọa (chưa cách ly được)",
                         f"{v.name}: {top_reason(v)} — {e}", data)
    elif wanted or v.label == MALICIOUS:
        db.add_event(source, "threat", "Phát hiện mối đe dọa", f"{v.name}: {top_reason(v)}", data)
    else:
        db.add_event(source, "warning", "Tệp đáng ngờ", f"{v.name}: {top_reason(v)} (điểm {v.score})", data)
    return out
