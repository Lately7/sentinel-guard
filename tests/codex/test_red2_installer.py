"""RED2 installer trust-boundary regression tests; no service or elevation."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

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
    assert next(item.sha256 for item in plan if item.source == reviewed) == original_hash
    reviewed.write_bytes(b"harmless changed module")
    target = tmp_path / "protected-version"

    with pytest.raises(installer.InstallError) as failure:
        installer.write_runtime(plan, target)
    assert failure.value.code == "INSTALL_INTEGRITY"


# A medium-integrity process replaces checkout Python; the elevated script executes its bytes.
@pytest.mark.xfail(
    strict=True,
    reason="Deferred pending owner question 15 in docs/handoff/PLAN.md §6: changing the install flow requires an owner decision",
)
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
