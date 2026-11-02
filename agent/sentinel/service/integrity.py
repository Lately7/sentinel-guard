"""Fail closed before importing the service backend from installed code."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
from pathlib import Path

from .paths import STATE_CHILDREN


class IntegrityError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def check_runtime(version: Path, *, path: list[str] | None = None, isolated: int | None = None,
                  dont_write: bool | None = None, pycache_prefix: str | None = None,
                  modules: dict[str, object] | None = None, executable: str | None = None,
                  prefix: str | None = None) -> None:
    version = version.resolve(strict=True)
    expected = [version / name for name in ("Lib", "DLLs", "app", "vendor")]
    actual = sys.path if path is None else path
    if [os.path.normcase(os.path.realpath(p)) for p in actual] != [os.path.normcase(str(p)) for p in expected]:
        raise IntegrityError("INSTALL_INTEGRITY", "sys.path")
    if (sys.flags.isolated if isolated is None else isolated) != 1:
        raise IntegrityError("INSTALL_INTEGRITY", "isolated mode")
    if not (sys.dont_write_bytecode if dont_write is None else dont_write):
        raise IntegrityError("INSTALL_INTEGRITY", "bytecode writes")
    if (sys.pycache_prefix if pycache_prefix is None else pycache_prefix) is not None:
        raise IntegrityError("INSTALL_INTEGRITY", "pycache prefix")
    for label, raw in (("executable", executable or sys.executable), ("prefix", prefix or sys.prefix)):
        if not _inside(Path(raw), version):
            raise IntegrityError("INSTALL_INTEGRITY", label)
    loaded = sys.modules if modules is None else modules
    sentinel = loaded.get("sentinel")
    if sentinel is None or not _inside(Path(getattr(sentinel, "__file__", "")), version / "app"):
        raise IntegrityError("INSTALL_INTEGRITY", "sentinel module")
    yara = loaded.get("yara_x")
    if yara is not None and not _inside(Path(getattr(yara, "__file__", "")), version / "vendor"):
        raise IntegrityError("INSTALL_INTEGRITY", "yara_x module")
    for name, mod in loaded.items():
        file = getattr(mod, "__file__", None)
        if file and str(file).lower().endswith((".pyd", ".dll")) and not _inside(Path(file), version):
            raise IntegrityError("INSTALL_INTEGRITY", name)
    dll = next(version.glob("python[0-9]*.dll"), None)
    if dll is None or not _inside(dll, version):
        raise IntegrityError("INSTALL_INTEGRITY", "Python DLL")
    if os.name == "nt":
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.SetDefaultDllDirectories.argtypes = [ctypes.c_ulong]
        k32.SetDefaultDllDirectories.restype = ctypes.c_int
        if not k32.SetDefaultDllDirectories(0x200 | 0x800):
            raise IntegrityError("INSTALL_INTEGRITY", "DLL search policy")
        k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        k32.GetModuleHandleW.restype = ctypes.c_void_p
        k32.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
        k32.GetModuleFileNameW.restype = ctypes.c_ulong
        for name in (dll.name, "python3.dll"):
            handle = k32.GetModuleHandleW(name)
            if handle:
                buf = ctypes.create_unicode_buffer(32768)
                count = k32.GetModuleFileNameW(handle, buf, len(buf))
                if not count or count >= len(buf) or not _inside(Path(buf.value), version):
                    raise IntegrityError("INSTALL_INTEGRITY", name)


def check_manifest(version: Path) -> None:
    try:
        hashes = json.loads((version / "manifest.json").read_text(encoding="utf-8"))["sha256"]
        for name, expected in hashes.items():
            p = version / name
            if not _inside(p, version) or hashlib.sha256(p.read_bytes()).hexdigest() != expected:
                raise IntegrityError("INSTALL_INTEGRITY", name)
    except (OSError, ValueError, KeyError) as exc:
        raise IntegrityError("INSTALL_INTEGRITY", str(exc)) from exc


def check_state(root: Path) -> None:
    for directory in (root, *(root / name for name in STATE_CHILDREN)):
        try:
            stat = directory.lstat()
            if not directory.is_dir() or getattr(stat, "st_file_attributes", 0) & 0x400:
                raise IntegrityError("STATE_ACL_UNSAFE", str(directory))
        except OSError as exc:
            raise IntegrityError("STATE_ACL_UNSAFE", str(directory)) from exc
    # An ACL check is mandatory; unsupported platforms must fail closed.
    if os.name != "nt":
        raise IntegrityError("STATE_ACL_UNSAFE", "Windows ACL unavailable")
    from .installer import InstallError, verify_protected_tree
    try:
        verify_protected_tree(root)
    except InstallError as exc:
        raise IntegrityError("STATE_ACL_UNSAFE", str(exc)) from exc


def startup_check(version: Path, state_root: Path) -> None:
    check_runtime(version)
    if os.name != "nt":
        raise IntegrityError("INSTALL_INTEGRITY", "Windows required")
    from .installer import InstallError, WindowsScm, verify_code_tree
    try:
        sid = WindowsScm().service_sid("SentinelGuard")
        verify_code_tree(version.parent.parent, sid)
    except (InstallError, OSError) as exc:
        raise IntegrityError("INSTALL_INTEGRITY", str(exc)) from exc
    check_manifest(version)
    check_state(state_root)
