"""Select bounded evidence without hiding a later conclusive detection."""

from __future__ import annotations

from dataclasses import replace

from .contract import Evidence, Strength
from .coverage import CoverageLedger

_ORDER = {Strength.CONCLUSIVE: 0, Strength.STRONG: 1,
          Strength.SUPPORTING: 2, Strength.CONTEXT: 3, Strength.COVERAGE: 4}


def select_evidence(items: list[Evidence], ledger: CoverageLedger) -> tuple[Evidence, ...]:
    counts: dict[tuple[str, str], int] = {}
    selected: list[Evidence] = []
    for item in sorted(items, key=lambda value: _ORDER[value.strength]):
        if item.strength is Strength.CONCLUSIVE:
            selected.append(item)
            continue
        # Same rule repeated across archive members collapses into one counted
        # item; different rules (namespace is part of evidence_id) and outer
        # versus member scope stay separate.
        key = (item.evidence_id, item.scope)
        if key in counts:
            counts[key] += 1
        else:
            counts[key] = 1
            selected.append(item)
    if any(count > 1 for count in counts.values()):
        selected = [replace(item, detail_code=f"{item.detail_code}_COUNT_{counts[(item.evidence_id, item.scope)]}")
                    if item.strength is not Strength.CONCLUSIVE and
                    counts[(item.evidence_id, item.scope)] > 1 else item
                    for item in selected]
    if len(selected) != len(items) or len(selected) > 64:
        ledger.limit("EVIDENCE_CAP")
    return tuple(selected[:64])
