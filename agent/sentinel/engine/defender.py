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
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

from .verdict import Finding, Severity

_THREAT_RE = re.compile(r"^\s*Threat\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
# Another AV can be installed or removed while the agent runs; re-ask after this.
ACTIVE_TTL = 600.0

Status = Literal["clean", "malicious", "error", "timeout", "unavailable"]
# (argv, timeout) -> (returncode, stdout); raises subprocess.TimeoutExpired or OSError.
Runner = Callable[[list[str], float], tuple[int, str]]


@dataclass(frozen=True)
class DefenderResult:
    status: Status
    findings: tuple[Finding, ...] = ()
    detail: str = ""

    @property
    def engine_status(self) -> str:
        """The text recorded in Verdict.engines; only a completed scan says "clean"."""
        if self.status == "clean":
            return "clean"
        if self.status == "malicious":
            return "detected"
        return f"{self.status}: {self.detail}" if self.detail else self.status


def _run(argv: list[str], timeout: float) -> tuple[int, str]:
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False, creationflags=NO_WINDOW)
    return proc.returncode, proc.stdout or ""


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


_active: tuple[float, bool] | None = None


def is_active(*, refresh: bool = False) -> bool:
    """Whether Defender is the running antivirus (not passive behind another product).

    With another AV installed (Malwarebytes here) Defender is off and
    MpCmdRun fails every scan with exit code 2 — the same code it uses for
    "threat found" — so it must not be asked at all. The answer is cached
    for ACTIVE_TTL seconds, not for the life of the process.
    """
    global _active
    now = time.monotonic()
    if not refresh and _active is not None and now - _active[0] < ACTIVE_TTL:
        return _active[1]
    _active = (now, _query_active())
    return _active[1]


def _query_active() -> bool:
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


def scan(path: str, timeout: float = 90.0, *, runner: Runner | None = None) -> DefenderResult:
    exe = mpcmdrun_path()
    if not exe:
        return DefenderResult("unavailable", detail="MpCmdRun.exe not found")
    if not Path(path).is_file():
        return DefenderResult("error", detail="file vanished before the Defender scan")
    argv = [exe, "-Scan", "-ScanType", "3", "-File", str(Path(path).resolve()), "-DisableRemediation"]
    try:
        returncode, stdout = (runner or _run)(argv, timeout)
    except subprocess.TimeoutExpired:
        return DefenderResult("timeout", detail=f"no answer within {timeout:g} s")
    except OSError as e:
        return DefenderResult("error", detail=str(e))
    return parse_result(returncode, stdout)


def parse_result(returncode: int, stdout: str) -> DefenderResult:
    # Exit code 2 means "threat found" *or* "scan failed"; only a named
    # threat in the output is evidence, and a failure is never "clean".
    names = sorted({m.group(1).strip() for m in _THREAT_RE.finditer(stdout)} - {""})
    if returncode == 2 and names:
        f = Finding("defender", "defender.detection", Severity.CRITICAL, f"Microsoft Defender: {', '.join(names)}", 100)
        return DefenderResult("malicious", (f,))
    if returncode == 0:
        return DefenderResult("clean")
    last = next((ln.strip() for ln in reversed(stdout.splitlines()) if ln.strip()), "")
    return DefenderResult("error", detail=f"MpCmdRun exit {returncode}" + (f": {last[:160]}" if last else ""))
