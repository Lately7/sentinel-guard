"""Paths and settings. Everything lives under one per-user data directory."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

HOST_NAME = "com.sentinelguard.host"
EXTENSION_ID = "ljnncmaoolpbiifaidkgekkeimmjlcgn"

# Hard limits so a hostile file can never make the scanner read unbounded data.
MAX_DEEP_SCAN_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 2000
MAX_ARCHIVE_DEPTH = 3


def data_dir() -> Path:
    # SENTINEL_HOME lets tests and portable installs keep state elsewhere.
    override = os.environ.get("SENTINEL_HOME")
    if override:
        base = Path(override)
    else:
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "SentinelGuard"
    base.mkdir(parents=True, exist_ok=True)
    return base


def db_path() -> Path:
    return data_dir() / "sentinel.db"


def quarantine_dir() -> Path:
    p = data_dir() / "quarantine"
    p.mkdir(parents=True, exist_ok=True)
    return p


def user_rules_dir() -> Path:
    p = data_dir() / "rules"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _default_watch_dirs() -> list[str]:
    home = Path.home()
    dirs = [home / "Downloads", home / "Desktop", home / "Documents"]
    appdata = os.environ.get("APPDATA")
    if appdata:
        dirs.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    temp = os.environ.get("TEMP")
    if temp:
        dirs.append(Path(temp))
    return [str(d) for d in dirs]


@dataclass
class Settings:
    realtime: bool = True
    watch_dirs: list[str] = field(default_factory=_default_watch_dirs)
    auto_quarantine: bool = True
    use_defender: bool = True  # ask Microsoft Defender for a second opinion
    feed_interval_hours: float = 6.0
    web_block_suspicious: bool = False  # suspicious URLs get a warning page only when True

    @staticmethod
    def path() -> Path:
        return data_dir() / "settings.json"

    @classmethod
    def load(cls) -> "Settings":
        try:
            raw = json.loads(cls.path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        known = {k: v for k, v in raw.items() if k in cls.__dataclass_fields__}
        try:
            return cls(**known)
        except TypeError:
            return cls()

    def save(self) -> None:
        self.path().write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8")
