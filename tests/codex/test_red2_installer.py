"""RED2 installer trust-boundary regression tests; no service or elevation."""

from __future__ import annotations

import hashlib
from pathlib import Path

from sentinel.service import installer


def _source(root: Path) -> Path:
    root.mkdir()
    for name in ("python.exe", "pythonw.exe", "python3.dll", "python315.dll",
                 "app/sentinel/__init__.py"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(name.encode())
    return root


def _script() -> str:
    return (Path(__file__).resolve().parents[2] / "tools" / "install_service.cmd").read_text(
        encoding="utf-8"
    ).lower()


# A medium-integrity process changes the reviewed snapshot; LocalSystem installs the changed bytes.
def test_red2_snapshot_change_after_plan_is_rejected(tmp_path: Path, sentinel_home: Path) -> None:
    source = _source(tmp_path / "snapshot")
    reviewed = source / "app" / "sentinel" / "__init__.py"
    original_hash = hashlib.sha256(reviewed.read_bytes()).hexdigest()
    plan = installer.plan_runtime(source)
    reviewed.write_bytes(b"harmless changed module")
    target = tmp_path / "protected-version"

    try:
        installer.write_runtime(plan, target)
    except installer.InstallError as error:
        assert error.code == "INSTALL_INTEGRITY"
    else:
        copied = target / "app" / "sentinel" / "__init__.py"
        assert hashlib.sha256(copied.read_bytes()).hexdigest() == original_hash


# A medium-integrity process replaces checkout Python; the elevated script executes its bytes.
def test_red2_elevated_script_does_not_execute_checkout_python(tmp_path: Path, sentinel_home: Path) -> None:
    checkout = tmp_path / "checkout"
    python = checkout / ".venv" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"harmless replacement executable")
    script = _script()

    elevates_checkout = ("start-process -verb runas" in script
                         and 'cd /d "%~dp0.."' in script)
    runs_checkout_python = any(line.lstrip().startswith(r".venv\scripts\python.exe ")
                               for line in script.splitlines())
    assert not (elevates_checkout and runs_checkout_python)


# A medium-integrity process reads the elevated service log copied into the user's TEMP.
def test_red2_service_log_is_not_copied_to_user_temp(tmp_path: Path, sentinel_home: Path) -> None:
    user_temp = tmp_path / "user-temp"
    user_temp.mkdir()
    script = _script()

    assert not ('set "log=%temp%\\sentinel-install.log"' in script
                and "get-content -literalpath" in script
                and "sentinelguard\\journal\\service.log" in script)
