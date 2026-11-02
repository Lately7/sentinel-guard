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

_THREAT_RE = re.compile(r"Threat\s*:\s*(.+)", re.IGNORECASE)


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


def available() -> bool:
    return mpcmdrun_path() is not None


def scan(path: str, timeout: float = 90.0) -> list[Finding]:
    exe = mpcmdrun_path()
    if not exe or not Path(path).is_file():
        return []
    argv = [exe, "-Scan", "-ScanType", "3", "-File", str(Path(path).resolve()), "-DisableRemediation"]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    # MpCmdRun exits 2 when a threat was found, 0 when clean.
    if proc.returncode != 2:
        return []
    names = [m.group(1).strip() for m in _THREAT_RE.finditer(proc.stdout or "")]
    label = ", ".join(sorted(set(names))) or "threat"
    return [Finding("defender", "defender.detection", Severity.CRITICAL, f"Microsoft Defender: {label}", 100)]
