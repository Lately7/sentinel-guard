"""Versioned, side-effect-free scan contracts and policy."""

from .contract import (
    CONTRACT_VERSION, EVENT_VERSION, ActionCode, ActionDecision, ByteRange,
    Category, ContractError, Coverage, EngineResult, Evidence, FileIdentity,
    FinalDecision, ScanError, ScanEvent, ScanRequest, StageStatus, Strength,
    VerdictCode,
)
from .policy import RequiredStages, classify_clamav_name, decide, should_auto_quarantine

__all__ = [
    "CONTRACT_VERSION", "EVENT_VERSION", "ActionCode", "ActionDecision",
    "ByteRange", "Category", "ContractError", "Coverage", "EngineResult",
    "Evidence", "FileIdentity", "FinalDecision", "RequiredStages",
    "ScanError", "ScanEvent", "ScanRequest", "StageStatus", "Strength",
    "VerdictCode", "classify_clamav_name", "decide", "should_auto_quarantine",
]
