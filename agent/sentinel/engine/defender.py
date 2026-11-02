"""Second opinion from Microsoft Defender's command-line scanner.

Defender has a far larger signature set than any feed we can download, so
asking it about risky files raises coverage at no cost. Remediation is
disabled: Sentinel Guard decides what to quarantine and keeps the record.
"""

from __future__ import annotations

import glob
import os
import re
import subprocess
from functools import lru_cache
from pathlib import Path

from .verdict import Finding, Severity

_THREAT_RE = re.compile(r"^\s*Threat\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


@lru_cache(maxsize=1)
def mpcmdrun_path() -> str | None:
    if os.name != "nt":
        return None
    candidates = sorted(
        glob.glob(os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                               "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe")),
        reverse=True,  # newest platform version first
    )
    candidates.append(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe"))
    for c in candidates:
        if Path(c).is_file():
            return c
    return None


@lru_cache(maxsize=1)
def is_active() -> bool:
    """Whether Defender is the running antivirus (not passive behind another product).

    With another AV installed (Malwarebytes here) Defender is off and
    MpCmdRun fails every scan with exit code 2 — the same code it uses for
    "threat found" — so it must not be asked at all.
    """
    if os.name != "nt":
        return False
    script = ("(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
              "| Where-Object displayName -eq 'Windows Defender').productState")
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                              capture_output=True, text=True, timeout=20, shell=False, creationflags=NO_WINDOW)
        state = int((proc.stdout or "").strip().splitlines()[0])
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        return False
    return bool(state & 0x1000)  # Security Center "real-time protection on" bit


def available() -> bool:
    return mpcmdrun_path() is not None and is_active()


def scan(path: str, timeout: float = 90.0) -> list[Finding]:
    exe = mpcmdrun_path()
    if not exe or not Path(path).is_file():
        return []
    argv = [exe, "-Scan", "-ScanType", "3", "-File", str(Path(path).resolve()), "-DisableRemediation"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False, creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return parse_result(proc.returncode, proc.stdout or "")


def parse_result(returncode: int, stdout: str) -> list[Finding]:
    # Exit code 2 means "threat found" *or* "scan failed"; only a named
    # threat in the output is evidence.
    names = sorted({m.group(1).strip() for m in _THREAT_RE.finditer(stdout)} - {""})
    if returncode != 2 or not names:
        return []
    return [Finding("defender", "defender.detection", Severity.CRITICAL, f"Microsoft Defender: {', '.join(names)}", 100)]
