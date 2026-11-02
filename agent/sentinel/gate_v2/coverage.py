"""Bounded byte and child-object coverage accounting without I/O."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from .contract import ByteRange, ContractError, Coverage

MAX_STORED_REASONS = 64
MAX_RANGES = 4096
MAX_CHILDREN = 2000
_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")


def normalize_ranges(ranges: tuple[ByteRange, ...], input_size: int) -> tuple[ByteRange, ...]:
    if input_size < 0:
        raise ContractError("INVALID_INPUT_SIZE")
    if len(ranges) > MAX_RANGES:
        raise ContractError("RANGE_LIMIT")
    for item in ranges:
        if item.end > input_size:
            raise ContractError("OUT_OF_BOUNDS_RANGE")
    merged: list[ByteRange] = []
    for item in sorted(ranges, key=lambda value: (value.start, value.end)):
        if item.start == item.end:
            continue
        if merged and item.start <= merged[-1].end:
            merged[-1] = ByteRange(merged[-1].start, max(merged[-1].end, item.end))
        else:
            merged.append(item)
    return tuple(merged)


def contains_range(ranges: tuple[ByteRange, ...], target: ByteRange) -> bool:
    return any(item.start <= target.start and target.end <= item.end for item in ranges)


@dataclass
class CoverageLedger:
    input_size: int
    inspected: tuple[ByteRange, ...] = ()
    certainty: Literal["verified", "declared", "unknown"] = "unknown"
    fixed_reduction: bool = False
    max_children: int = MAX_CHILDREN
    objects_seen: int = 0
    objects_inspected: int = 0
    objects_opaque: int = 0
    objects_omitted: int = 0
    object_reasons: list[str] = field(default_factory=list)
    reasons_overflow: int = 0
    parser_states: list[tuple[str, str]] = field(default_factory=list)
    limits_hit: list[str] = field(default_factory=list)
    enumeration_complete: bool = True

    def __post_init__(self) -> None:
        if self.input_size < 0:
            raise ContractError("INVALID_INPUT_SIZE")
        if self.max_children < 0:
            raise ContractError("INVALID_CHILD_LIMIT")
        self.inspected = normalize_ranges(self.inspected, self.input_size)

    def child(self, state: Literal["inspected", "opaque", "omitted"], reason: str | None = None) -> None:
        if state not in ("inspected", "opaque", "omitted"):
            raise ContractError("INVALID_CHILD_STATE")
        if state != "inspected" and (not reason or not _REASON.fullmatch(reason)):
            raise ContractError("MISSING_CHILD_REASON")
        if self.objects_seen >= self.max_children:
            state, reason = "omitted", "MAX_CHILDREN"
            self.limit("MAX_CHILDREN")
            self.enumeration_complete = False
        self.objects_seen += 1
        if state == "inspected":
            self.objects_inspected += 1
        else:
            if state == "opaque":
                self.objects_opaque += 1
            else:
                self.objects_omitted += 1
            if len(self.object_reasons) < MAX_STORED_REASONS - 1:
                self.object_reasons.append(reason or "")
            else:
                self.reasons_overflow += 1

    def limit(self, code: str) -> None:
        if not code or not _REASON.fullmatch(code):
            raise ContractError("INVALID_LIMIT_CODE")
        if code not in self.limits_hit:
            if len(self.limits_hit) >= MAX_STORED_REASONS:
                raise ContractError("LIMIT_REASON_CAP")
            self.limits_hit.append(code)

    def parser(self, parser_id: str, state: str) -> None:
        if len(self.parser_states) >= MAX_STORED_REASONS:
            self.limit("PARSER_STATE_CAP")
            self.enumeration_complete = False
            return
        if max(len(parser_id), len(state)) > 128:
            raise ContractError("INVALID_PARSER_STATE")
        self.parser_states.append((parser_id, state))
        if state != "complete":
            self.enumeration_complete = False

    def finish(self) -> Coverage:
        full_bytes = self.inspected == ((ByteRange(0, self.input_size),) if self.input_size else ())
        debt = bool(self.objects_opaque or self.objects_omitted or self.limits_hit or not self.enumeration_complete)
        if full_bytes and not debt and not self.fixed_reduction:
            mode = "full"
        elif self.fixed_reduction and not debt:
            mode = "fixed_partial"
        elif self.inspected or debt:
            mode = "runtime_partial"
        else:
            mode = "none"
        reasons = tuple(self.object_reasons)
        if self.reasons_overflow:
            reasons += ("REASONS_OVERFLOW",)
        return Coverage(
            self.input_size, self.inspected, mode, self.objects_seen,
            self.objects_inspected, self.objects_opaque, self.objects_omitted,
            reasons, tuple(self.parser_states), tuple(self.limits_hit), self.certainty,
        )
