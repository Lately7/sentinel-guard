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
# Above this a file is reported as not scanned; measuring it is a full read.
# Provisional, like the deadline, until they are measured on the owner's machine.
MAX_SCAN_BYTES = 4 * 1024 * 1024 * 1024
SCAN_DEADLINE_SECONDS = 120.0


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


_KNOWN_FOLDERS = {
    # FOLDERID GUIDs; resolving them follows OneDrive Known Folder Move and
    # other redirection, unlike Path.home() / "Desktop".
    "Downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
    "Desktop": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
    "Documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
}


def known_folder(name: str) -> Path:
    fallback = Path.home() / name
    if os.name != "nt":
        return fallback
    try:
        import ctypes
        import uuid
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                        ("Data4", ctypes.c_ubyte * 8)]

        u = uuid.UUID(_KNOWN_FOLDERS[name])
        g = GUID(u.time_low, u.time_mid, u.time_hi_version, (ctypes.c_ubyte * 8)(*u.bytes[8:]))
        out = ctypes.c_wchar_p()
        shell32 = ctypes.WinDLL("shell32")
        ole32 = ctypes.WinDLL("ole32")
        if shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(out)) != 0:
            return fallback
        try:
            return Path(out.value) if out.value else fallback
        finally:
            ole32.CoTaskMemFree(out)
    except (OSError, AttributeError, KeyError, ValueError):
        return fallback


def _default_watch_dirs() -> list[str]:
    dirs = [known_folder("Downloads"), known_folder("Desktop"), known_folder("Documents")]
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
    use_clamav: bool = True  # stream every file through a private clamd (if ClamAV is installed)
    feed_interval_hours: float = 6.0
    web_block_suspicious: bool = False  # suspicious URLs get a warning page only when True
    abusech_auth_key: str = ""  # free abuse.ch account key: enables the MalwareBazaar hash feed

    @staticmethod
    def path() -> Path:
        return data_dir() / "settings.json"

    @classmethod
    def load(cls) -> "Settings":
        try:
            raw = json.loads(cls.path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        s = cls()
        if not isinstance(raw, dict):
            return s
        # Each field is type-checked on its own: one bad value falls back to
        # its default instead of crashing the agent at start-up.
        for name in ("realtime", "auto_quarantine", "use_defender", "use_clamav", "web_block_suspicious"):
            if isinstance(raw.get(name), bool):
                setattr(s, name, raw[name])
        dirs = raw.get("watch_dirs")
        if isinstance(dirs, list) and all(isinstance(d, str) and d for d in dirs):
            s.watch_dirs = dirs
        key = raw.get("abusech_auth_key")
        if isinstance(key, str) and len(key) <= 200 and key.isprintable():
            s.abusech_auth_key = key.strip()
        hours = raw.get("feed_interval_hours")
        if isinstance(hours, (int, float)) and not isinstance(hours, bool) and 0.25 <= hours <= 24 * 30:
            s.feed_interval_hours = float(hours)
        return s

    def save(self) -> None:
        self.path().write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8")
