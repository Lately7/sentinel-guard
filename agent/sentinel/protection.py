"""What happens after a verdict: quarantine, event log. Shared by the watcher, CLI and native host."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from . import quarantine
from .config import Settings
from .db import Database
from .engine.verdict import CLEAN, MALICIOUS, Finding, Severity, Verdict
from .gate_v2.contract import ActionCode
from .gate_v2.legacy import UNKNOWN

log = logging.getLogger(__name__)

# Set in processes that run beside the service: while it answers, the action is
# its own, decided on its own scan (R13b P9). Returns None when no service answers.
delegate: Callable[[Verdict], dict[str, Any] | None] | None = None


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


def escalate_origin(v: Verdict, reputation: dict[str, Any] | None) -> None:
    # The browser tried to cancel this download because of the same URL verdict
    # and lost the race; the verdict stays authoritative whatever the list's kind
    # (phishing kits ship droppers too).
    if reputation and reputation["verdict"] == "malicious" and v.label != MALICIOUS:
        v.findings.append(Finding("origin", "origin.blocklisted_download", Severity.CRITICAL,
                                  f"downloaded from {reputation['matched']} ({reputation['kind']}, {reputation['source']})",
                                  100))


NOT_QUARANTINED_VI = {
    "NOT_CONFIRMED": "dịch vụ quét lại không xác nhận được phát hiện này",
    "CHANGED": "tệp đã đổi sau khi quét, sẽ quét lại",
    "IN_USE": "tệp đang chạy hoặc đang được dùng, hãy đóng chương trình rồi quét lại",
    "MISSING": "tệp không còn ở đó",
    "ACCESS_DENIED": "không có quyền với tệp này",
    "PROTECTED_PATH": "tệp nằm trong thư mục hệ thống, không tự cách ly",
    "REPARSE_POINT": "đường dẫn là liên kết, không cách ly qua liên kết",
}


def _quarantine(db: Database, v: Verdict, data: dict[str, Any], authority: bool) -> str:
    done = delegate(v) if delegate is not None and not authority else None
    if done is not None:
        if done.get("quarantine_id"):
            return str(done["quarantine_id"])
        error = quarantine.QuarantineError(str(done.get("error") or "not confirmed"), str(done.get("code") or "NOT_CONFIRMED"))
        error.repair_id = done.get("repair_id")  # type: ignore[attr-defined]
        raise error
    decision = getattr(v, "decision", None)
    return quarantine.quarantine(db, str(v.path), data, expected=decision.identity if decision else None)


def act_on(db: Database, v: Verdict, settings: Settings, source: str,
           *, extra: dict[str, Any] | None = None, authority: bool = False) -> dict[str, Any]:
    """Record and (for malicious files) quarantine. Returns {label, quarantined, quarantine_id, error}.

    `authority` is the service acting for itself: there is nobody left to ask.
    """
    out: dict[str, Any] = {"label": v.label, "quarantined": False, "quarantine_id": None, "error": None}
    if v.label == CLEAN or not v.path:
        return out
    data = {**v.to_dict(), **(extra or {})}
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
            qid = _quarantine(db, v, data, authority)
            out.update(quarantined=True, quarantine_id=qid)
            db.add_event(source, "threat", "Đã cách ly mối đe dọa",
                         f"{v.name}: {top_reason(v)}", {**data, "quarantine_id": qid})
        except quarantine.QuarantineError as e:
            why = NOT_QUARANTINED_VI.get(e.code, "không cách ly được")
            out.update(error=why, code=e.code, repair_id=getattr(e, "repair_id", None))
            log.warning("quarantine of %s failed: %s", v.name, e)
            db.add_event(source, "threat", "Phát hiện mối đe dọa (chưa cách ly được)",
                         f"{v.name}: {top_reason(v)} — {why}", data)
    elif wanted or v.label == MALICIOUS:
        db.add_event(source, "threat", "Phát hiện mối đe dọa", f"{v.name}: {top_reason(v)}", data)
    else:
        db.add_event(source, "warning", "Tệp đáng ngờ", f"{v.name}: {top_reason(v)} (điểm {v.score})", data)
    return out
