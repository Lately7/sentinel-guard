"""Download free public threat-intelligence feeds into a new indicator snapshot.

Each feed is independent: a network error or format change in one is recorded
in the `feeds` table and that feed keeps its previous entries.
"""

from __future__ import annotations

import dataclasses
import logging
import re
import time
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Settings

from . import __version__, urlintel
from .db import Database
from .indicators import SnapshotBuilder, publish
from .singleton import FEEDS_MUTEX, NamedLock

log = logging.getLogger(__name__)

# A failed signature update is retried after this, not after the full period:
# advancing the success time on failure left ClamAV 4 h and YARA 24 h stale.
ENGINE_RETRY_AFTER = 30 * 60


def engine_update_due(db: Database, key: str, period: float, now: float | None = None) -> bool:
    """Whether the engine database `key` ("clamav", "yara") should be refreshed now."""
    now = time.time() if now is None else now
    last_ok = float(db.get_meta(f"{key}_updated", "0") or 0)
    last_try = float(db.get_meta(f"{key}_attempted", "0") or 0)
    return now - last_ok > period and now - last_try > ENGINE_RETRY_AFTER


def record_engine_update(db: Database, key: str, result: str, now: float | None = None) -> None:
    now = time.time() if now is None else now
    db.set_meta(f"{key}_attempted", str(now))
    if result.startswith("ok"):
        db.set_meta(f"{key}_updated", str(now))


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
    headers: tuple[tuple[str, str], ...] = ()  # e.g. an account key; never logged


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
# Benchmark (reports/web-eval.json): with the top 10k protected, 0.2% of
# Tranco ranks 10k-20k were still host-blocked by aggregate feeds.
POPULAR_TOP = 100_000
MAX_TRANCO_CSV_BYTES = 64 * 1024 * 1024


def parse_tranco(raw: bytes, top: int = POPULAR_TOP) -> list[str]:
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        csvs = [i for i in zf.infolist() if i.filename.lower().endswith(".csv")]
        if not csvs:
            raise ValueError("Tranco archive has no CSV")
        info = csvs[0]
        if info.file_size > MAX_TRANCO_CSV_BYTES:
            raise ValueError("Tranco CSV larger than limit")
        with zf.open(info) as fh:
            # Bounded read: a lying header can't make us decompress more than the limit.
            text = fh.read(MAX_TRANCO_CSV_BYTES + 1)
    if len(text) > MAX_TRANCO_CSV_BYTES:
        raise ValueError("Tranco CSV larger than limit")
    domains = []
    for line in text.decode("utf-8", errors="replace").splitlines():
        _rank, _, dom = line.partition(",")
        dom = dom.strip().lower()
        if dom:
            domains.append(dom)
            if len(domains) >= top:
                break
    if len(domains) < top // 2:
        raise ValueError("Tranco list looks truncated")
    return domains


def _fetch_bytes(url: str, timeout: float = 120.0, headers: dict[str, str] | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"SentinelGuard/{__version__} (+feed updater)", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("download larger than limit")
    return data


def fetch(url: str, headers: dict[str, str] | None = None) -> str:
    return _fetch_bytes(url, headers=headers).decode("utf-8", errors="replace")


_TABLE = {"bad_hosts": "hosts", "bad_urls": "urls", "bad_hashes": "hashes"}


def apply_feed(builder: SnapshotBuilder, feed: Feed, text: str, popular: frozenset[str]) -> int:
    """Parse one feed into the snapshot being built. Raises if nothing usable was parsed."""
    items = list(dict.fromkeys(feed.parse(text)))
    if feed.table == "bad_hosts":
        # Feeds occasionally list a hugely popular domain by mistake; blocking
        # it wholesale would break the web, so such entries are dropped.
        items = [h for h in items if urlintel.registrable_domain(h) not in popular]
    if not items:
        # An empty parse usually means the format changed or an error page was
        # served; the caller keeps the previous data instead.
        raise ValueError("no indicators parsed")
    if feed.table == "bad_hashes":
        builder.add_hashes((h, feed.name, None) for h in items)
    elif feed.table == "bad_hosts":
        builder.add_hosts((h, feed.kind, feed.name) for h in items)
    else:
        builder.add_urls((u, feed.kind, feed.name) for u in items)
        # Phishing URLs on dedicated hosts also block the host, so variants
        # of the same lure page are caught; shared platforms stay URL-only.
        if feed.kind == "phishing":
            hosts = {h for u in items if (h := urlintel.host_of(u)) and not urlintel.is_shared_platform(h)
                     and urlintel.registrable_domain(h) not in popular}
            builder.add_hosts((h, feed.kind, feed.name) for h in hosts)
    return len(items)


def _carry_over(db: Database, builder: SnapshotBuilder, feed: Feed, popular: frozenset[str]) -> int:
    table = _TABLE[feed.table]
    rows = db.indicators.rows_for_source(table, feed.name)

    def unpopular(host_rows: list[tuple]) -> list[tuple]:
        # Same exclusion as fresh data: today's popular list may cover a host
        # that was admitted while Tranco itself was unavailable.
        return [r for r in host_rows if urlintel.registrable_domain(r[0]) not in popular]

    if table == "hosts":
        rows = unpopular(rows)
        builder.add_hosts(rows)
    elif table == "urls":
        builder.add_urls(rows)
        builder.add_hosts(unpopular(db.indicators.rows_for_source("hosts", feed.name)))
    else:
        builder.add_hashes(rows)
    return len(rows)


# MalwareBazaar's export needs a free abuse.ch account key since 2025; with
# one configured (settings.json "abusech_auth_key") it is added automatically.
MALWAREBAZAAR = Feed("malwarebazaar", "https://bazaar.abuse.ch/export/txt/sha256/recent/", "bad_hashes", "malware", parse_hashes)


def configured_feeds(settings: "Settings") -> list[Feed]:
    feeds = list(FEEDS)
    if settings.abusech_auth_key:
        feeds.append(dataclasses.replace(MALWAREBAZAAR, headers=(("Auth-Key", settings.abusech_auth_key),)))
    return feeds


def last_update(db: Database) -> float:
    """Time of the last successful update of any feed (0 if never)."""
    return max((f["updated"] or 0 for f in db.feed_status() if str(f["status"]).startswith("ok")), default=0.0)


def is_due(db: Database, interval_hours: float, now: float | None = None) -> bool:
    if db.indicators.outdated:  # old snapshot format: rebuild without waiting for the interval
        return True
    return (now if now is not None else time.time()) - last_update(db) > interval_hours * 3600


def update_all(db: Database, feeds: list[Feed] | None = None, fetcher: Callable[[str], str] = fetch,
               fetch_bytes: Callable[[str], bytes] | None = None) -> dict[str, str]:
    """Build and publish a new snapshot. One process at a time: a second caller gets {"skipped": ...}."""
    lock = NamedLock(FEEDS_MUTEX)
    if not lock.acquire():
        return {"skipped": "another feed update is already running"}
    try:
        if feeds is None:
            from .config import Settings

            chosen = configured_feeds(Settings.load())
        else:
            chosen = feeds
        return _update_all(db, chosen, fetcher, fetch_bytes or _fetch_bytes, with_tranco=feeds is None)
    finally:
        lock.release()


def _update_all(db: Database, feeds: list[Feed], fetcher: Callable[[str], str],
                fetch_bytes: Callable[[str], bytes], with_tranco: bool) -> dict[str, str]:
    results: dict[str, str] = {}
    statuses: list[tuple[str, int | None, str]] = []
    builder = SnapshotBuilder()
    try:
        popular: frozenset[str]
        if with_tranco:
            try:
                domains = parse_tranco(fetch_bytes(TRANCO_URL))
                popular = frozenset(domains)
                statuses.append(("tranco_top", len(domains), "ok"))
                results["tranco_top"] = f"ok ({len(domains)})"
            except Exception as e:
                popular = db.indicators.popular()
                statuses.append(("tranco_top", None, f"error: {e}"))
                results["tranco_top"] = f"error: {e} (kept previous list)"
        else:
            popular = db.indicators.popular()
        popular = popular | db.popular_domains()
        builder.set_popular(popular)

        for feed in feeds:
            try:
                text = fetch(feed.url, dict(feed.headers)) if feed.headers else fetcher(feed.url)
                n = apply_feed(builder, feed, text, popular)
                statuses.append((feed.name, n, "ok"))
                results[feed.name] = f"ok ({n})"
            except Exception as e:  # one broken feed must not stop the others
                log.warning("feed %s failed: %s", feed.name, e)
                kept = _carry_over(db, builder, feed, popular)
                statuses.append((feed.name, None, f"error: {e}"))
                results[feed.name] = f"error: {e} (kept {kept} previous entries)"
        path = builder.finish()
    except BaseException:
        builder.discard()
        raise
    publish(db, path)
    for name, n, status in statuses:
        db.set_feed(name, n, status)
    return results
