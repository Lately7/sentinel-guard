"""URL / host reputation from the local indicator database."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .db import Database

# Shared hosting / file-sharing platforms: feeds list individual URLs on them,
# and blocking the whole host would break the web for the user. These are only
# ever matched at full-URL level.
SHARED_PLATFORMS = frozenset("""
github.com raw.githubusercontent.com objects.githubusercontent.com gist.github.com githubusercontent.com
gitlab.com bitbucket.org google.com docs.google.com drive.google.com sites.google.com storage.googleapis.com
googleusercontent.com firebasestorage.googleapis.com dropbox.com dl.dropboxusercontent.com onedrive.live.com
1drv.ms sharepoint.com microsoft.com live.com cdn.discordapp.com discord.com media.discordapp.net
mediafire.com mega.nz amazonaws.com s3.amazonaws.com cloudfront.net azureedge.net blob.core.windows.net
web.core.windows.net pages.dev workers.dev github.io netlify.app vercel.app herokuapp.com glitch.me
facebook.com fbcdn.net instagram.com t.me telegram.org youtube.com bit.ly tinyurl.com is.gd
pastebin.com transfer.sh wetransfer.com archive.org sourceforge.net
""".split())

TRUSTED_SCHEMES = ("http", "https")


def normalize_url(url: str) -> str | None:
    """Lower-case scheme/host, drop fragment and default port: the form feeds and lookups agree on."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme.lower() not in TRUSTED_SCHEMES or not parts.hostname:
        return None
    host = parts.hostname.lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        return None
    netloc = host if port is None or (parts.scheme.lower(), port) in (("http", 80), ("https", 443)) else f"{host}:{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def host_of(url: str) -> str | None:
    try:
        h = urlsplit(url.strip()).hostname
    except ValueError:
        return None
    return h.lower().rstrip(".") if h else None


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def parent_hosts(host: str) -> list[str]:
    """`a.b.evil.com` -> [a.b.evil.com, b.evil.com, evil.com]; IPs map to themselves."""
    if is_ip(host):
        return [host]
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)] or [host]


_MULTI_PART_SUFFIXES = frozenset("""
co.uk org.uk ac.uk gov.uk com.vn net.vn org.vn edu.vn gov.vn info.vn biz.vn ac.vn com.au net.au org.au edu.au
gov.au co.jp ne.jp or.jp ac.jp go.jp com.br net.br org.br gov.br com.cn net.cn org.cn gov.cn edu.cn co.kr or.kr
go.kr ac.kr com.sg edu.sg gov.sg com.my com.ph co.th in.th co.id or.id go.id co.in net.in org.in gov.in ac.in
com.tw org.tw edu.tw com.hk org.hk com.mx com.ar com.tr co.za co.nz
""".split())


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1 without a full public-suffix list (mirrors the extension's version)."""
    host = host.lower().rstrip(".")
    if is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_shared_platform(host: str) -> bool:
    return any(h in SHARED_PLATFORMS for h in parent_hosts(host))


def check(db: Database, url: str) -> dict[str, Any]:
    """Reputation verdict for one URL: {verdict, kind, source, matched, allowed}."""
    norm = normalize_url(url)
    host = host_of(url)
    result: dict[str, Any] = {"url": url, "verdict": "unknown", "kind": None, "source": None, "matched": None, "allowed": False}
    if not norm or not host:
        result["verdict"] = "ignored"
        return result
    if any(db.is_host_allowed(h) for h in parent_hosts(host)):
        result.update(verdict="allowed", allowed=True)
        return result
    for candidate in (norm, norm.rstrip("/")):
        row = db.url_info(candidate)
        if row:
            result.update(verdict="malicious", kind=row["kind"], source=row["source"], matched=row["url"])
            return result
    for h in parent_hosts(host):
        row = db.host_info(h)
        if row:
            result.update(verdict="malicious", kind=row["kind"], source=row["source"], matched=row["host"])
            return result
    return result
