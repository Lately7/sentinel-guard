"""Protected installed paths; portable installs continue to use config.py."""

from __future__ import annotations

import ctypes
import os
import re
import sys
import uuid
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

FOLDERID_PROGRAM_FILES = "{905E63B6-C1BF-494E-B29C-65B732D3D21A}"
FOLDERID_PROGRAM_DATA = "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}"
STATE_CHILDREN = ("db", "feeds", "policy", "journal", "quarantine", "handoff", "staging")
VERSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


def known_folder(folder_id: str) -> Path:
    if os.name != "nt":
        raise OSError("Windows Known Folders are required")
    u = uuid.UUID(folder_id)
    guid = GUID(u.time_low, u.time_mid, u.time_hi_version, (ctypes.c_ubyte * 8)(*u.bytes[8:]))
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    ole = ctypes.WinDLL("ole32", use_last_error=True)
    shell.SHGetKnownFolderPath.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE,
                                          ctypes.POINTER(ctypes.c_wchar_p)]
    shell.SHGetKnownFolderPath.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    out = ctypes.c_wchar_p()
    hr = shell.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out))
    if hr != 0 or not out.value:
        raise OSError(hr, "SHGetKnownFolderPath failed")
    try:
        return Path(out.value)
    finally:
        ole.CoTaskMemFree(ctypes.cast(out, ctypes.c_void_p))


@dataclass(frozen=True)
class InstalledPaths:
    code_root: Path
    state_root: Path
    version: Path

    @property
    def python(self) -> Path:
        return self.version / "python.exe"

    @property
    def pythonw(self) -> Path:
        return self.version / "pythonw.exe"

    def state(self, child: str) -> Path:
        if child not in STATE_CHILDREN:
            raise ValueError("unknown state directory")
        return self.state_root / child


def installed_paths(version_id: str, *, program_files: Path | None = None,
                    program_data: Path | None = None) -> InstalledPaths:
    if not VERSION_ID.fullmatch(version_id) or version_id in (".", ".."):
        raise ValueError("invalid version id")
    code = (program_files or known_folder(FOLDERID_PROGRAM_FILES)) / "SentinelGuard"
    state = (program_data or known_folder(FOLDERID_PROGRAM_DATA)) / "SentinelGuard"
    return InstalledPaths(code, state, code / "versions" / version_id)


def active_version() -> Path | None:
    """The fixed interpreter layout, never an environment override."""
    exe = Path(sys.executable).resolve()
    if exe.parent.parent.name.lower() != "versions" or exe.parent.parent.parent.name.lower() != "sentinelguard":
        return None
    return exe.parent
