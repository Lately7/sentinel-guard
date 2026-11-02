"""Native-messaging host: the browser extension's bridge to the local engine.

The browser starts this process and talks over stdin/stdout with 4-byte
little-endian length-prefixed JSON. Messages to the browser are capped at
1 MB, so the blocklist is paged.
"""

from __future__ import annotations

import json
import logging
import os
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, BinaryIO

from . import __version__, config, urlintel
from .db import Database
from .engine.scanner import Scanner
from .protection import act_on, escalate_origin, top_reason
from .service.bridge import ServiceLease, install

log = logging.getLogger("sentinel.nativehost")

MAX_IN = 1024 * 1024
MAX_OUT = 1024 * 1024  # Chromium's limit for host -> browser messages
PAGE_LIMIT = 20_000
PAGE_BYTES = 600_000
_MAX_STR = 8192
# A confirmation can wait on the user for minutes; URL lookups must not.
SLOW_TYPES = {"scan_download", "allow_host"}


class BadRequest(Exception):
    pass


def _str(msg: dict[str, Any], key: str, required: bool = True, max_len: int = _MAX_STR) -> str | None:
    v = msg.get(key)
    if v is None and not required:
        return None
    if not isinstance(v, str) or not v or len(v) > max_len:
        raise BadRequest(f"'{key}' must be a non-empty string up to {max_len} chars")
    return v


def _int(msg: dict[str, Any], key: str, default: int, lo: int, hi: int) -> int:
    v = msg.get(key, default)
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise BadRequest(f"'{key}' must be an integer in [{lo}, {hi}]")
    return v


class Host:
    def __init__(self, db: Database, settings: config.Settings, lease: ServiceLease | None = None) -> None:
        self.db = db
        self.settings = settings
        self.lease = lease  # while a service answers, it decides; this process only asks
        self._scanner: Scanner | None = None
        self._bl_cache: tuple[str, list[tuple[str, str]]] | None = None

    @property
    def scanner(self) -> Scanner:
        # Built lazily: most messages are URL lookups and must answer instantly.
        if self._scanner is None:
            self._scanner = Scanner(self.db, use_defender=self.settings.use_defender,
                                    use_clamav=self.settings.use_clamav)
        return self._scanner

    def handle(self, msg: Any) -> dict[str, Any]:
        if not isinstance(msg, dict):
            return {"ok": False, "error": "message must be an object"}
        rid = msg.get("id")
        if rid is not None and not isinstance(rid, (int, str)):
            rid = None
        try:
            kind = _str(msg, "type", max_len=64)
            fn = getattr(self, f"on_{kind}", None)
            if fn is None:
                raise BadRequest(f"unknown type {kind!r}")
            out = fn(msg)
            out.update(ok=True)
        except BadRequest as e:
            out = {"ok": False, "error": str(e)}
        except Exception as e:
            log.exception("handler failed")
            out = {"ok": False, "error": f"internal error: {type(e).__name__}"}
        out["id"] = rid
        return out

    def on_hello(self, msg: dict[str, Any]) -> dict[str, Any]:
        # The dashboard shows when the browser extension last checked in.
        self.db.set_meta("extension_seen", str(time.time()))
        service = self.lease.status() if self.lease is not None else None
        return {"version": __version__, "blocklist_version": self.db.get_meta("blocklist_version", "0"),
                "allow_version": f"s{service['allow_version']}" if service else self.db.allow_version(),
                "counts": self.db.counts()}

    def on_check_url(self, msg: dict[str, Any]) -> dict[str, Any]:
        url = _str(msg, "url")
        assert url is not None
        answer = self.lease.check_url(url) if self.lease is not None else None
        return {"result": answer if answer is not None else urlintel.check(self.db, url)}

    def _blocklist(self) -> tuple[str, list[tuple[str, str]]]:
        # One snapshot per (blocklist, allowlist) version: paging through
        # 400k hosts must not re-run the full query for every page.
        key = f"{self.db.get_meta('blocklist_version', '0')}/{self.db.allow_version()}"
        if self._bl_cache is None or self._bl_cache[0] != key:
            self._bl_cache = (key, self.db.blocked_hosts())
        return self._bl_cache

    def on_get_blocklist(self, msg: dict[str, Any]) -> dict[str, Any]:
        offset = _int(msg, "offset", 0, 0, 10_000_000)
        limit = _int(msg, "limit", PAGE_LIMIT, 1, PAGE_LIMIT)
        version, hosts = self._blocklist()
        page: list[list[str]] = []
        size = 0
        # Bounded by encoded size, not count: the browser drops the whole
        # connection on any message over 1 MB.
        for host, kind in hosts[offset:offset + limit]:
            size += len(host) + len(kind) + 8
            if size > PAGE_BYTES and page:
                break
            page.append([host, kind])
        return {"version": version, "total": len(hosts), "offset": offset, "hosts": page}

    def on_get_allowlist(self, msg: dict[str, Any]) -> dict[str, Any]:
        # Paged like the blocklist (RT-021: it used to stop silently at 5,000
        # hosts). Callers without an offset get the first page.
        offset = _int(msg, "offset", 0, 0, 10_000_000)
        limit = _int(msg, "limit", PAGE_LIMIT, 1, PAGE_LIMIT)
        service = self.lease.allowed_hosts(offset, limit) if self.lease is not None else None
        if service is not None:
            return {**service, "allow_version": f"s{service['allow_version']}"}
        version = self.db.allow_version()
        everything = self.db.allowed_hosts()
        hosts: list[str] = []
        size = 0
        for h in everything[offset:offset + limit]:
            size += len(h) + 4
            if size > PAGE_BYTES and hosts:
                break
            hosts.append(h)
        return {"allow_version": version, "total": len(everything), "offset": offset, "hosts": hosts}

    def on_scan_download(self, msg: dict[str, Any]) -> dict[str, Any]:
        path = _str(msg, "path", max_len=4096)
        assert path is not None
        url = _str(msg, "url", required=False)
        p = Path(path)
        if not p.is_absolute() or not p.is_file():
            raise BadRequest("path must be an existing absolute file path")
        done = self.lease.scan_download(path, url) if self.lease is not None else None
        if done is not None:
            # A scan the service could not finish must not read as a result.
            if done.get("state") != "done" or "verdict" not in done:
                raise BadRequest(f"the service did not finish this scan ({done.get('code', 'unknown')})")
            return {k: done.get(k) for k in ("verdict", "reason", "url_reputation", "label", "quarantined",
                                             "quarantine_id", "error")}
        rep = urlintel.check(self.db, url) if url else None
        v = self.scanner.scan_file(p, use_cache=False)
        escalate_origin(v, rep)
        outcome = act_on(self.db, v, self.settings, "download")
        return {"verdict": v.to_dict(max_findings=30), "reason": top_reason(v), "url_reputation": rep, **outcome}

    def on_report(self, msg: dict[str, Any]) -> dict[str, Any]:
        action = _str(msg, "action", max_len=32)
        url = _str(msg, "url")
        reason = _str(msg, "reason", required=False, max_len=1000) or ""
        titles = {"blocked": ("threat", "Đã chặn trang web nguy hiểm"),
                  "warned": ("warning", "Cảnh báo trang web rủi ro"),
                  "proceeded": ("warning", "Người dùng vẫn mở trang bị cảnh báo"),
                  "download_blocked": ("threat", "Đã chặn tải xuống nguy hiểm"),
                  "page_threat": ("warning", "Phát hiện hành vi đáng ngờ trên trang")}
        if action not in titles:
            raise BadRequest("unknown report action")
        level, title = titles[action]
        self.db.add_event("web", level, title, f"{url} — {reason}" if reason else str(url),
                          {"url": url, "action": action, "reason": reason})
        return {}

    def on_allow_host(self, msg: dict[str, Any]) -> dict[str, Any]:
        host = _str(msg, "host", max_len=253)
        assert host is not None
        host = host.lower().strip(".")
        if not host or "/" in host or " " in host:
            raise BadRequest("invalid host")
        if self.lease is not None and self.lease.available():
            # A page can ask for this; only an administrator's confirmation grants it.
            if not self.lease.approve("trust_host", {"host": host}):
                raise BadRequest("not approved")
            return {}
        self.db.allow_host(host)
        self.db.add_event("web", "warning", "Đã tin cậy trang web", host, {"host": host})
        return {}


def _read_exact(stream: BinaryIO, n: int) -> bytes | None:
    """Read exactly n bytes; None if the stream ends first.

    A pipe may hand back fewer bytes than asked for; treating a short read as
    the whole frame would parse half a message and desynchronise every frame
    after it.
    """
    parts: list[bytes] = []
    remaining = n
    while remaining > 0:
        part = stream.read(remaining)
        if not part:
            return None
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


def read_message(stream: BinaryIO) -> Any | None:
    raw_len = _read_exact(stream, 4)
    if raw_len is None:
        return None
    (n,) = struct.unpack("<I", raw_len)
    if n > MAX_IN:
        # Drain so the stream stays in sync, in chunks: one read(n) of a
        # 4 GB length prefix would try to allocate it all at once.
        remaining = n
        while remaining > 0:
            part = stream.read(min(remaining, 1024 * 1024))
            if not part:
                return None
            remaining -= len(part)
        return {"type": "__too_large__"}
    data = _read_exact(stream, n)
    if data is None:
        return None  # the browser closed the pipe mid-message
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return {"type": "__bad_json__"}


_write_lock = threading.Lock()


def origin_allowed(argv: list[str]) -> bool:
    """The browser passes the caller's origin; only our extension may talk to the host.

    A missing origin is refused too: it means someone started the host by hand.
    `--diagnostic` is the explicit way to do that for debugging.
    """
    if "--diagnostic" in argv:
        log.warning("native host started in diagnostic mode without an origin check")
        return True
    origin = next((a for a in argv if a.startswith("chrome-extension://")), None)
    if origin is None or origin.rstrip("/") != f"chrome-extension://{config.EXTENSION_ID}":
        log.warning("rejected origin %s", origin)
        return False
    return True


def write_message(stream: BinaryIO, obj: dict[str, Any]) -> None:
    # Escaped: a lone surrogate is a legal NTFS name and has no UTF-8 form.
    data = json.dumps(obj, separators=(",", ":")).encode("ascii")
    if len(data) > MAX_OUT:
        # Sending it would make the browser kill the connection; answer with
        # an error the extension can handle instead.
        data = json.dumps({"id": obj.get("id"), "ok": False, "error": "response too large"}).encode("utf-8")
    with _write_lock:  # scan workers and the main loop share stdout
        stream.write(struct.pack("<I", len(data)))
        stream.write(data)
        stream.flush()


def main(argv: list[str]) -> int:
    logging.basicConfig(filename=str(config.data_dir() / "nativehost.log"), level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if not origin_allowed(argv):
        return 1
    if os.name == "nt":
        import msvcrt

        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)  # type: ignore[attr-defined]
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)  # type: ignore[attr-defined]
    host = Host(Database(), config.Settings.load(), install())
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    # File scans can take a minute (Defender); they run on workers so URL
    # lookups for the next navigation are answered immediately.
    workers = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan")
    while True:
        msg = read_message(stdin)
        if msg is None:
            workers.shutdown(wait=True)
            return 0
        if isinstance(msg, dict) and msg.get("type") in SLOW_TYPES:
            workers.submit(lambda m=msg: write_message(stdout, host.handle(m)))
        else:
            write_message(stdout, host.handle(msg))
