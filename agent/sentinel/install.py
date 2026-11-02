"""Per-user install: native-messaging host registration and autostart. No admin rights needed."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from . import config

# Registry keys browsers read native-messaging hosts from. Helium (and other
# ungoogled-chromium builds) use the Chromium key.
BROWSER_KEYS = {
    "Helium / Chromium": r"Software\Chromium\NativeMessagingHosts",
    "Google Chrome": r"Software\Google\Chrome\NativeMessagingHosts",
    "Microsoft Edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
    "Brave": r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
}
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "SentinelGuard"


def helium_exe() -> Path | None:
    p = Path(os.environ.get("LOCALAPPDATA", "")) / "imput" / "Helium" / "Application" / "chrome.exe"
    return p if p.is_file() else None


def extension_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "extension"


def _pythonw() -> str:
    exe = Path(sys.executable)
    w = exe.with_name("pythonw.exe")
    return str(w if w.is_file() else exe)


def write_host_files() -> Path:
    d = config.data_dir() / "native"
    d.mkdir(parents=True, exist_ok=True)
    launcher = d / "sentinel-host.cmd"
    # Browsers can only launch an executable path, not "python -m"; the .cmd
    # pins the interpreter that has this package installed.
    launcher.write_text(f'@echo off\r\n"{sys.executable}" -m sentinel native-host %*\r\n', encoding="ascii")
    manifest = d / f"{config.HOST_NAME}.json"
    manifest.write_text(json.dumps({
        "name": config.HOST_NAME,
        "description": "Sentinel Guard local protection engine",
        "path": str(launcher),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{config.EXTENSION_ID}/"],
    }, indent=2), encoding="utf-8")
    return manifest


def install(autostart: bool = True) -> list[str]:
    import winreg

    manifest = write_host_files()
    done = []
    for browser, key in BROWSER_KEYS.items():
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{key}\\{config.HOST_NAME}") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, str(manifest))
        done.append(f"native host registered for {browser}")
    if autostart:
        cmd = subprocess.list2cmdline([_pythonw(), "-m", "sentinel", "tray"])
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, cmd)
        done.append("autostart at sign-in enabled")
    return done


def uninstall() -> list[str]:
    import winreg

    done = []
    for browser, key in BROWSER_KEYS.items():
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, f"{key}\\{config.HOST_NAME}")
            done.append(f"native host removed for {browser}")
        except OSError:
            pass
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, RUN_NAME)
        done.append("autostart removed")
    except OSError:
        pass
    return done


def open_helium_extensions() -> bool:
    exe = helium_exe()
    if not exe:
        return False
    subprocess.Popen([str(exe), "chrome://extensions/"], shell=False)
    return True
