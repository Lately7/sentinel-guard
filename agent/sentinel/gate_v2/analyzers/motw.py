"""Untrusted, bounded Zone.Identifier origin context."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from .. import identity
from ..content import BoundReader
from ..contract import (CancellationToken, Category, EngineResult, FileIdentity,
                        ScanRequest, StageStatus, Strength)
from . import context_evidence, result

MAX_TEXT = 8192
MAX_URL = 2048
Reader = Callable[[str], str | None]


def read_zone(path: str) -> str | None:
    if os.name != "nt":
        return None
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as stream:
            return stream.read(MAX_TEXT + 1)
    except OSError:
        return None


@dataclass(frozen=True)
class Origin:
    zone: int | None
    host_url: str | None
    referrer_url: str | None
    malformed: bool


def parse(text: str) -> Origin:
    if not isinstance(text, str) or len(text) > MAX_TEXT:
        return Origin(None, None, None, True)
    zone = None
    host = None
    referrer = None
    malformed = False
    section = False
    for line in text.splitlines():
        item = line.strip()
        if not item or item.startswith((";", "#")):
            continue
        if item.lower() == "[zonetransfer]":
            section = True
            continue
        if item.startswith("["):
            section = False
            continue
        if "=" not in item:
            malformed = True
            continue
        if not section:
            continue
        key, value = (part.strip() for part in item.split("=", 1))
        if key.lower() == "zoneid":
            if re.fullmatch(r"[0-4]", value):
                zone = int(value)
            else:
                malformed = True
        elif key.lower() in ("hosturl", "referrerurl"):
            if len(value) > MAX_URL or any(ord(char) < 32 for char in value):
                malformed = True
            elif key.lower() == "hosturl":
                host = value or None
            else:
                referrer = value or None
    return Origin(zone, host, referrer, malformed)


class MotwAdapter:
    engine_id = "motw"
    reopens_path = False

    def __init__(self, reader: Reader = read_zone) -> None:
        self.reader = reader

    def readiness(self) -> str:
        return "READY"

    def scan_bound(self, request: ScanRequest, measured: FileIdentity,
                   cancel: CancellationToken, reader: BoundReader) -> EngineResult:
        start = time.monotonic_ns()
        if cancel.cancelled():
            return result(self.engine_id, request, measured, start, StageStatus.CANCELLED,
                          "CANCELLED", (), parser_state="cancelled")
        if request.path is None:
            return result(self.engine_id, request, measured, start, StageStatus.UNAVAILABLE,
                          "PATH_REQUIRED", (), parser_state="unavailable")
        try:
            if not identity.revalidate(request.path, measured, rehash=True).ok:
                return result(self.engine_id, request, measured, start, StageStatus.CHANGED,
                              "CHANGED", (), parser_state="changed")
            raw = self.reader(request.path)
            if not identity.revalidate(request.path, measured, rehash=True).ok:
                return result(self.engine_id, request, measured, start, StageStatus.CHANGED,
                              "CHANGED", (), parser_state="changed")
            if raw is None:
                return result(self.engine_id, request, measured, start, StageStatus.UNAVAILABLE,
                              "ZONE_STREAM_ABSENT", (), parser_state="unavailable")
            origin = parse(raw)
            codes = []
            if origin.zone is not None:
                codes.append(f"ZONE_{origin.zone}")
            if origin.host_url:
                codes.append("HOST_URL_PRESENT")
            if origin.referrer_url:
                codes.append("REFERRER_URL_PRESENT")
            evidence = tuple(context_evidence(self.engine_id, code, Category.ORIGIN,
                                              Strength.CONTEXT, (), scope="origin")
                             for code in codes)
            if origin.malformed:
                return result(self.engine_id, request, measured, start, StageStatus.PARTIAL,
                              "MOTW_MALFORMED", (), evidence, parser_state="malformed")
            return result(self.engine_id, request, measured, start, StageStatus.COMPLETED,
                          "READY", (), evidence, certainty="declared")
        except Exception:
            return result(self.engine_id, request, measured, start, StageStatus.ERROR,
                          "MOTW_READ_ERROR", (), parser_state="error")
