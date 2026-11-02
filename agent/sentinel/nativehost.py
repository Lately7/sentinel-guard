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
from pathlib import Path
from typing import Any, BinaryIO

from . import __version__, config, urlintel
from .db import Database
from .engine.scanner import Scanner
from .protection import act_on, top_reason

log = logging.getLogger("sentinel.nativehost")

MAX_IN = 1024 * 1024
PAGE_LIMIT = 20_000
_MAX_STR = 8192


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
    def __init__(self, db: Database, settings: config.Settings) -> None:
        self.db = db
        self.settings = settings
        self._scanner: Scanner | None = None

    @property
    def scanner(self) -> Scanner:
        # Built lazily: most messages are URL lookups and must answer instantly.
        if self._scanner is None:
            self._scanner = Scanner(self.db, use_defender=self.settings.use_defender)
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
        return {"version": __version__, "blocklist_version": self.db.get_meta("blocklist_version", "0"),
                "counts": self.db.counts()}

    def on_check_url(self, msg: dict[str, Any]) -> dict[str, Any]:
        url = _str(msg, "url")
        assert url is not None
        return {"result": urlintel.check(self.db, url)}

    def on_get_blocklist(self, msg: dict[str, Any]) -> dict[str, Any]:
        offset = _int(msg, "offset", 0, 0, 10_000_000)
        limit = _int(msg, "limit", PAGE_LIMIT, 1, PAGE_LIMIT)
        all_hosts = self.db.blocked_hosts()
        page = all_hosts[offset:offset + limit]
        return {"version": self.db.get_meta("blocklist_version", "0"), "total": len(all_hosts),
                "offset": offset, "hosts": [[h, k] for h, k in page]}

    def on_scan_download(self, msg: dict[str, Any]) -> dict[str, Any]:
        path = _str(msg, "path", max_len=4096)
        assert path is not None
        url = _str(msg, "url", required=False)
        p = Path(path)
        if not p.is_absolute() or not p.is_file():
            raise BadRequest("path must be an existing absolute file path")
        v = self.scanner.scan_file(p, use_cache=False)
        outcome = act_on(self.db, v, self.settings, "download")
        rep = urlintel.check(self.db, url) if url else None
        return {"verdict": v.to_dict(), "reason": top_reason(v), "url_reputation": rep, **outcome}

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
        self.db.allow_host(host)
        self.db.add_event("web", "warning", "Đã tin cậy trang web", host, {"host": host})
        return {}


def read_message(stream: BinaryIO) -> Any | None:
    raw_len = stream.read(4)
    if len(raw_len) < 4:
        return None
    (n,) = struct.unpack("<I", raw_len)
    if n > MAX_IN:
        stream.read(n)  # drain so the stream stays in sync
        return {"type": "__too_large__"}
    data = stream.read(n)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"type": "__bad_json__"}


def write_message(stream: BinaryIO, obj: dict[str, Any]) -> None:
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack("<I", len(data)))
    stream.write(data)
    stream.flush()


def main(argv: list[str]) -> int:
    logging.basicConfig(filename=str(config.data_dir() / "nativehost.log"), level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    # The browser passes the caller's origin; refuse anything but our extension.
    origin = next((a for a in argv if a.startswith("chrome-extension://")), None)
    if origin and origin.rstrip("/") != f"chrome-extension://{config.EXTENSION_ID}":
        log.warning("rejected origin %s", origin)
        return 1
    if os.name == "nt":
        import msvcrt

        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)  # type: ignore[attr-defined]
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)  # type: ignore[attr-defined]
    host = Host(Database(), config.Settings.load())
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    while True:
        msg = read_message(stdin)
        if msg is None:
            return 0
        write_message(stdout, host.handle(msg))
