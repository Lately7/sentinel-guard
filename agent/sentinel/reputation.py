"""abuse.ch API feeds and the optional VirusTotal lookup; both need the owner's key.

Used only with a key in settings: nothing here runs on a default install, and
VirusTotal is not wired to anything yet. It sends a hash, never a file, and its
answer is supporting evidence, never a conclusion.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from . import urlintel
from .feeds import Feed, apply_feed
from .indicators import SnapshotBuilder

MAX_RESPONSE = 4 * 1024 * 1024
MAX_ROWS = 100_000
_HASH = re.compile(r"^[0-9a-fA-F]{64}$")


class Transport(Protocol):
    def __call__(self, url: str, headers: Mapping[str, str], body: bytes | None,
                 limit: int) -> bytes: ...


@dataclass(frozen=True)
class ParseResult:
    values: tuple[str, ...]
    skipped: int
    truncated: int = 0


@dataclass(frozen=True)
class Lookup:
    status: str  # DISABLED | SUPPORTING | NO_HIT | GAP
    malicious: int = 0
    total: int = 0
    reason: str = ""


def _rows(raw: bytes, field: str, limit: int) -> tuple[list[object], int]:
    if len(raw) > limit:
        raise ValueError("reputation response exceeds byte cap")
    doc = json.loads(raw)
    rows = doc.get(field) if isinstance(doc, dict) else None
    if not isinstance(rows, list):
        raise ValueError("missing reputation rows")
    return rows[:MAX_ROWS], max(0, len(rows) - MAX_ROWS)


def _parse(raw: bytes, field: str, key: str, kind: str, limit: int = MAX_RESPONSE) -> ParseResult:
    rows, truncated = _rows(raw, field, limit)
    found: list[str] = []
    skipped = 0
    for row in rows:
        value = row.get(key) if isinstance(row, dict) else None
        if kind == "hash":
            valid = isinstance(value, str) and bool(_HASH.fullmatch(value))
            normalized = value.lower() if valid else None
        else:
            normalized = urlintel.normalize_url(value) if isinstance(value, str) else None
        if normalized is None:
            skipped += 1
        else:
            found.append(normalized)
    return ParseResult(tuple(dict.fromkeys(found)), skipped, truncated)


def parse_malwarebazaar(raw: bytes, limit: int = MAX_RESPONSE) -> ParseResult:
    return _parse(raw, "data", "sha256_hash", "hash", limit)


def parse_urlhaus(raw: bytes, limit: int = MAX_RESPONSE) -> ParseResult:
    return _parse(raw, "urls", "url", "url", limit)


def parse_threatfox(raw: bytes, limit: int = MAX_RESPONSE) -> ParseResult:
    if len(raw) > limit:
        raise ValueError("reputation response exceeds byte cap")
    doc = json.loads(raw)
    rows = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(rows, list):
        raise ValueError("missing reputation rows")
    found: list[str] = []
    skipped = 0
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict) or row.get("ioc_type") not in ("sha256_hash", "sha256"):
            skipped += 1
            continue
        value = row.get("ioc")
        if not isinstance(value, str) or not _HASH.fullmatch(value):
            skipped += 1
            continue
        found.append(value.lower())
    return ParseResult(tuple(dict.fromkeys(found)), skipped, max(0, len(rows) - MAX_ROWS))


def parse_threatfox_urls(raw: bytes, limit: int = MAX_RESPONSE) -> ParseResult:
    rows, truncated = _rows(raw, "data", limit)
    found: list[str] = []
    skipped = 0
    for row in rows:
        value = row.get("ioc") if isinstance(row, dict) and row.get("ioc_type") == "url" else None
        normalized = urlintel.normalize_url(value) if isinstance(value, str) else None
        if normalized is None:
            skipped += 1
        else:
            found.append(normalized)
    return ParseResult(tuple(dict.fromkeys(found)), skipped, truncated)


@dataclass(frozen=True)
class Adapter:
    name: str
    url: str
    table: str
    kind: str
    body: bytes | None
    parser: Callable[[bytes, int], ParseResult]

    def fetch(self, transport: Transport, auth_key: str, limit: int = MAX_RESPONSE) -> ParseResult:
        if not auth_key:
            raise ValueError("abuse.ch key required")
        headers = {"Auth-Key": auth_key, "Content-Type": "application/json"}
        raw = transport(self.url, headers, self.body, limit + 1)
        if len(raw) > limit:
            raise ValueError("reputation response exceeds byte cap")
        return self.parser(raw, limit)

    def as_feed(self, result: ParseResult) -> Feed:
        # feeds.apply_feed performs snapshot deduplication and table insertion.
        return Feed(self.name, self.url, self.table, self.kind,
                    lambda _text: iter(result.values))

    def apply(self, builder: SnapshotBuilder, result: ParseResult,
              popular: frozenset[str] = frozenset()) -> int:
        return apply_feed(builder, self.as_feed(result), "", popular)


MALWAREBAZAAR = Adapter("malwarebazaar_api", "https://mb-api.abuse.ch/api/v1/",
                        "bad_hashes", "malware", b"query=get_recent&selector=100",
                        parse_malwarebazaar)
URLHAUS = Adapter("urlhaus_api", "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                   "bad_urls", "malware", None, parse_urlhaus)
THREATFOX = Adapter("threatfox_api", "https://threatfox-api.abuse.ch/api/v1/",
                     "bad_hashes", "malware", b'{"query":"get_iocs","days":1}',
                     parse_threatfox)
THREATFOX_URLS = Adapter("threatfox_urls_api", THREATFOX.url, "bad_urls", "malware",
                         THREATFOX.body, parse_threatfox_urls)


def http_transport(url: str, headers: Mapping[str, str], body: bytes | None, limit: int) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("https required")
    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST" if body else "GET")
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(limit)


def api_feeds(auth_key: str, transport: Transport = http_transport) -> list[Feed]:
    """The API-only sources; MalwareBazaar's bulk export is already a plain feed."""
    def pull(adapter: Adapter) -> str:
        raw = transport(adapter.url, {"Auth-Key": auth_key, "Content-Type": "application/json"}, adapter.body,
                        MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("reputation response exceeds byte cap")
        return raw.decode("utf-8")

    return [Feed(a.name, a.url, a.table, a.kind,
                 lambda text, a=a: iter(a.parser(text.encode("utf-8"), MAX_RESPONSE).values),
                 pull=lambda a=a: pull(a)) for a in (URLHAUS, THREATFOX, THREATFOX_URLS)]


class VirusTotal:
    """Hash-only download lookup; evidence is always supporting."""

    def __init__(self, transport: Transport, settings: object, *, interval: float = 15.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if interval < 15.0:
            raise ValueError("VirusTotal interval must be at least 15 seconds")
        self.transport, self.settings, self.interval, self.clock = transport, settings, interval, clock
        self._next = 0.0

    def lookup_download(self, sha256: str) -> Lookup:
        if not getattr(self.settings, "virustotal_enabled", False):
            return Lookup("DISABLED")
        key = getattr(self.settings, "virustotal_api_key", "")
        if not isinstance(key, str) or not key:
            return Lookup("GAP", reason="missing_key")
        if not isinstance(sha256, str) or not _HASH.fullmatch(sha256):
            return Lookup("GAP", reason="invalid_hash")
        now = self.clock()
        if now < self._next:
            return Lookup("GAP", reason="rate_limited")
        self._next = now + self.interval
        try:
            raw = self.transport(f"https://www.virustotal.com/api/v3/files/{sha256.lower()}",
                                 {"x-apikey": key}, None, 64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                return Lookup("GAP", reason="response_too_large")
            stats = json.loads(raw)["data"]["attributes"]["last_analysis_stats"]
            bad = stats["malicious"]
            if not isinstance(stats, dict) or any(type(v) is not int or v < 0 for v in stats.values()):
                raise ValueError("invalid counts")
            total = sum(stats.values())
            return Lookup("SUPPORTING" if bad else "NO_HIT", bad, total)
        except Exception:
            return Lookup("GAP", reason="lookup_failed")
