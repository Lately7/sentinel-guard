"""Download free public threat-intelligence feeds into the local DB.

Each feed is independent: a network error or format change in one is recorded
in the `feeds` table and the rest still update.
"""

from __future__ import annotations

import logging
import re
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from . import __version__, urlintel
from .db import Database

log = logging.getLogger(__name__)

MAX_FEED_BYTES = 80 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    table: str  # bad_hashes | bad_hosts | bad_urls
    kind: str
    parse: Callable[[str], Iterable[str]]


def _lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!", ";")):
            yield line


def parse_hashes(text: str) -> Iterable[str]:
    for line in _lines(text):
        tok = line.split(",")[0].strip().strip('"')
        if _SHA256_RE.match(tok):
            yield tok.lower()


def parse_urls(text: str) -> Iterable[str]:
    for line in _lines(text):
        norm = urlintel.normalize_url(line)
        if norm:
            yield norm


def parse_hosts(text: str) -> Iterable[str]:
    """Accepts plain domain lists and hosts-file lines (`0.0.0.0 evil.com`)."""
    for line in _lines(text):
        parts = line.split()
        host = parts[1] if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::") else parts[0]
        host = host.lower().rstrip(".")
        if host in ("localhost", "0.0.0.0", "broadcasthost") or not _HOST_RE.match(host):
            continue
        if urlintel.is_shared_platform(host):
            continue
        yield host


# abuse.ch's bulk exports (MalwareBazaar, URLhaus, ThreatFox) now answer 410
# without an account key; malware-filter republishes URLhaus as a domain list.
FEEDS: list[Feed] = [
    Feed("urlhaus_filter", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt", "bad_hosts", "malware", parse_hosts),
    Feed("phishing_filter", "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt", "bad_hosts", "phishing", parse_hosts),
    Feed("pup_filter", "https://malware-filter.gitlab.io/pup-filter/pup-filter-domains.txt", "bad_hosts", "pup", parse_hosts),
    Feed("openphish", "https://openphish.com/feed.txt", "bad_urls", "phishing", parse_urls),
    Feed("hagezi_tif", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt", "bad_hosts", "threat", parse_hosts),
    Feed("hagezi_fake", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt", "bad_hosts", "scam", parse_hosts),
    Feed("phishing_database", "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
         "bad_hosts", "phishing", parse_hosts),
    Feed("nocoin", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", "bad_hosts", "miner", parse_hosts),
]

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
POPULAR_TOP = 10_000


def update_popular(db: Database, fetch_bytes: Callable[[str], bytes] | None = None) -> int:
    """Load Tranco's most popular registrable domains: never blocked at host level."""
    import io
    import zipfile

    raw = (fetch_bytes or _fetch_bytes)(TRANCO_URL)
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        text = zf.read(zf.namelist()[0]).decode("utf-8", errors="replace")
    domains = []
    for line in text.splitlines()[:POPULAR_TOP]:
        _rank, _, dom = line.partition(",")
        dom = dom.strip().lower()
        if dom:
            domains.append(dom)
    if len(domains) < POPULAR_TOP // 2:
        raise ValueError("Tranco list looks truncated")
    db.set_popular(domains)
    return len(domains)


def _fetch_bytes(url: str, timeout: float = 120.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"SentinelGuard/{__version__} (+feed updater)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("download larger than limit")
    return data


def fetch(url: str) -> str:
    return _fetch_bytes(url).decode("utf-8", errors="replace")


def apply_feed(db: Database, feed: Feed, text: str) -> int:
    items = list(dict.fromkeys(feed.parse(text)))
    if feed.table == "bad_hosts":
        # Feeds occasionally list a hugely popular domain by mistake; blocking
        # it wholesale would break the web, so such entries are dropped.
        popular = db.popular_domains()
        items = [h for h in items if urlintel.registrable_domain(h) not in popular]
    if not items:
        # An empty parse usually means the format changed or an error page was
        # served; keeping yesterday's data is safer than wiping it.
        raise ValueError("no indicators parsed")
    db.replace_source(feed.table, feed.name)
    if feed.table == "bad_hashes":
        db.add_hashes((h, feed.name, None) for h in items)
    elif feed.table == "bad_hosts":
        db.add_hosts((h, feed.kind, feed.name) for h in items)
    else:
        db.add_urls((u, feed.kind, feed.name) for u in items)
        # Phishing URLs on dedicated hosts also block the host, so variants
        # of the same lure page are caught; shared platforms stay URL-only.
        if feed.kind == "phishing":
            db.replace_source("bad_hosts", feed.name)
            popular = db.popular_domains()
            hosts = {h for u in items if (h := urlintel.host_of(u)) and not urlintel.is_shared_platform(h)
                     and urlintel.registrable_domain(h) not in popular}
            db.add_hosts((h, feed.kind, feed.name) for h in hosts)
    return len(items)


def update_all(db: Database, feeds: list[Feed] | None = None, fetcher: Callable[[str], str] = fetch) -> dict[str, str]:
    results: dict[str, str] = {}
    if feeds is None:
        try:
            n = update_popular(db)
            db.set_feed("tranco_top", n, "ok")
            results["tranco_top"] = f"ok ({n})"
        except Exception as e:
            db.set_feed("tranco_top", None, f"error: {e}")
            results["tranco_top"] = f"error: {e}"
    for feed in feeds or FEEDS:
        try:
            n = apply_feed(db, feed, fetcher(feed.url))
            db.set_feed(feed.name, n, "ok")
            results[feed.name] = f"ok ({n})"
        except Exception as e:  # one broken feed must not stop the others
            log.warning("feed %s failed: %s", feed.name, e)
            db.set_feed(feed.name, None, f"error: {e}")
            results[feed.name] = f"error: {e}"
    db.bump_generation()
    db.set_meta("blocklist_version", str(db.generation()))
    return results
