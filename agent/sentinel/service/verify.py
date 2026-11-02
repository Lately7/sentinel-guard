"""`sentinel service verify`: one elevated command that proves the installed service.

The checks look at the real service, read-only apart from one temporary clean
file and an optional restart. Nothing here is a claim: each line is what was
measured, and what cannot be measured from an elevated prompt says SKIP.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import installer
from .client import ServiceClient, ServiceError
from .paths import InstalledPaths, installed_paths

NAME = "SentinelGuard"
# What lets a principal stop, pause, reconfigure or take over a service.
DANGEROUS_RIGHTS = ("WP", "DT", "DC", "WD", "WO", "SD", "GA", "GW")
ORDINARY_USERS = ("IU", "BU", "AU", "WD", "SU", "BG")
ACE = re.compile(r"\(A;[^;]*;([^;]*);[^;]*;[^;]*;([^)]*)\)")
PATH_IN_BIN = re.compile(r'"([^"]+)"')


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool | None  # None: not checked, which is different from passed
    detail: str = ""

    def line(self) -> str:
        word = "SKIP" if self.passed is None else "PASS" if self.passed else "FAIL"
        return f"{word} {self.name}" + (f": {self.detail}" if self.detail else "")


def sc(*args: str) -> str:
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "sc.exe")
    return subprocess.run([exe, *args], capture_output=True, timeout=60, check=False).stdout.decode("oem", "replace")


def ordinary_users_cannot_stop(sddl: str) -> bool:
    """False if any ordinary principal holds a right that can stop or change the service."""
    for rights, who in ACE.findall(sddl.strip()):
        if who not in ORDINARY_USERS:
            continue
        if rights.startswith("0x"):
            # SERVICE_STOP 0x20, PAUSE 0x40, CHANGE_CONFIG 0x2, DELETE, WRITE_DAC, WRITE_OWNER
            if int(rights, 16) & (0x20 | 0x40 | 0x2 | 0x00010000 | 0x00040000 | 0x00080000):
                return False
        elif any(rights[i:i + 2] in DANGEROUS_RIGHTS for i in range(0, len(rights), 2)):
            return False
    return bool(ACE.search(sddl))


def binary_of(qc: str) -> str | None:
    match = re.search(r"BINARY_PATH_NAME\s*:\s*(.+)", qc)
    if match is None:
        return None
    found = PATH_IN_BIN.search(match.group(1))
    return found.group(1) if found else None


def _version_paths(qc: str) -> InstalledPaths:
    exe = binary_of(qc)
    if exe is None:
        raise ValueError("service binary not found")
    return installed_paths(Path(exe).parent.name)


def _config(qc: str, query: str) -> tuple[bool, str]:
    exe = binary_of(qc) or ""
    if "RUNNING" not in query:
        return False, "not running"
    if "LocalSystem" not in qc:
        return False, "wrong account"
    if "-I -B -m sentinel.service.entry" not in qc:
        return False, "wrong command line"
    if not exe.lower().endswith(r"\python.exe") or r"\sentinelguard\versions" not in exe.lower():
        return False, f"binary outside the protected install: {exe}"
    return True, ""


def _imports(exe: str, version: Path) -> tuple[bool, str]:
    done = subprocess.run([exe, "-I", "-B", "-c", "import sys,json,sentinel;print(json.dumps([*sys.path,sentinel.__file__]))"],
                          capture_output=True, timeout=30, check=False, cwd=str(version))
    if done.returncode:
        return False, done.stderr.decode("oem", "replace")[:200]
    root = os.path.normcase(str(version)) + os.sep
    stray = [p for p in json.loads(done.stdout) if p and not os.path.normcase(p).startswith(root)]
    return not stray, f"outside the install: {stray[:3]}" if stray else ""


def _own_scan(client: ServiceClient) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as stream:
        stream.write(b"sentinel verify: harmless text\n")
    try:
        job = client.request("scan_request", path=os.path.realpath(stream.name))["job_id"]
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            info = client.request("job_status", job_id=job)
            if info["state"] in ("done", "failed", "cancelled"):
                break
            time.sleep(0.2)
        else:
            return False, "the scan did not finish"
        if info["state"] != "done" or "core" not in info.get("engines", ()):
            return False, f"{info['state']} {info.get('code', '')}"
        return info["verdict"]["label"] == "clean", f"worker answered: {info['verdict']['label']}"
    finally:
        os.unlink(stream.name)


def _refuses_unknown(client: ServiceClient) -> tuple[bool, str]:
    try:
        client.request("format_disk")
    except ServiceError as e:
        return e.code == "UNKNOWN_OP", e.code
    return False, "accepted"


def _observing(status: dict[str, Any]) -> tuple[bool | None, str]:
    seen = status.get("observation", {})
    if seen.get("prevention") != "none":
        return False, "status claims prevention"
    denied = seen.get("gap_access_denied", 0)
    if denied:
        return False, f"journal denied {denied} times"
    return True, f"records {seen.get('records', 0)}, failed polls {seen.get('failed_polls', 0)}"


def _restart() -> tuple[bool, str]:
    sc("stop", NAME)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        state = sc("query", NAME)
        if "STOPPED" in state:
            break
        time.sleep(0.5)
    else:
        return False, "did not stop in time"
    code = re.search(r"WIN32_EXIT_CODE\s*:\s*(\d+)", state)
    if code is None or code.group(1) != "0":
        return False, f"unclean stop: {code.group(1) if code else '?'}"
    sc("start", NAME)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if "RUNNING" in sc("query", NAME):
            return True, ""
        time.sleep(0.5)
    return False, "did not come back"


def run(*, restart: bool = False, client: Callable[[], ServiceClient] = ServiceClient) -> list[Check]:
    results: list[Check] = []

    def check(name: str, probe: Callable[[], tuple[bool | None, str]]) -> bool:
        try:
            passed, detail = probe()
        except (OSError, ValueError, KeyError, ServiceError, installer.InstallError, subprocess.SubprocessError) as e:
            passed, detail = False, f"{type(e).__name__}: {e}"
        results.append(Check(name, passed, detail))
        return passed is True

    if not check("elevated_token", lambda: (installer.WindowsScm().elevated(), "")):
        return results
    qc, query = sc("qc", NAME), sc("query", NAME)
    if not check("service_config", lambda: _config(qc, query)):
        return results
    paths = _version_paths(qc)
    check("sid_type", lambda: ("UNRESTRICTED" in sc("qsidtype", NAME).upper(), ""))
    check("privileges", lambda: ("SeImpersonatePrivilege" in sc("qprivs", NAME), ""))
    check("failure_actions", lambda: ("RESTART" in sc("qfailure", NAME).upper(), ""))
    check("users_cannot_stop", lambda: (ordinary_users_cannot_stop(sc("sdshow", NAME)), ""))
    check("runtime_hashes", lambda: (installer.verify_runtime(paths.version) is None, ""))
    check("state_acl", lambda: (installer.verify_protected_tree(paths.state_root) is None, ""))
    check("isolated_imports", lambda: _imports(str(paths.python), paths.version))
    with client() as service:
        if check("pipe_owner", lambda: (service.request("hello").get("protocol") is not None, "")):
            check("refuses_unknown_op", lambda: _refuses_unknown(service))
            check("worker_scan", lambda: _own_scan(service))
            check("observers", lambda: _observing(service.request("status")))
    results.append(Check("medium_token_cannot_approve", None, "needs an unelevated client: the tray's Khôi phục shows it"))
    results.append(Check("remote_client_refused", None, "needs a second machine"))
    if restart:
        check("clean_stop_and_start", _restart)
    return results


def main(*, restart: bool = False) -> int:
    results = run(restart=restart)
    for item in results:
        print(item.line())
    failed = [item for item in results if item.passed is False]
    print(f"{len(failed)} FAIL, {sum(1 for r in results if r.passed)} PASS, "
          f"{sum(1 for r in results if r.passed is None)} SKIP")
    return 1 if failed else 0
