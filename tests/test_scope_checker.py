"""tools/check_codex_scope.ps1 flags any file a Codex round touched outside its allowed paths."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "tools" / "check_codex_scope.ps1"

pytestmark = pytest.mark.skipif(os.name != "nt" or shutil.which("git") is None, reason="Windows PowerShell + git")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True, shell=False).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str]:
    r = tmp_path / "wt"
    r.mkdir()
    git(r, "init", "-q")
    git(r, "config", "user.email", "t@example.test")
    git(r, "config", "user.name", "t")
    (r / "agent").mkdir()
    (r / "agent" / "core.py").write_text("x = 1\n")
    git(r, "add", ".")
    git(r, "commit", "-q", "-m", "base")
    return r, git(r, "rev-parse", "HEAD")


def check(repo: Path, base: str, *allow: str) -> tuple[int, str]:
    p = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT),
                        "-Base", base, "-Allow", ",".join(allow)],
                       cwd=repo, capture_output=True, text=True, shell=False)
    return p.returncode, p.stdout


def test_changes_inside_scope_pass(repo):
    r, base = repo
    (r / "tests" / "codex").mkdir(parents=True)
    (r / "tests" / "codex" / "test_x.py").write_text("")
    (r / "reports").mkdir()
    (r / "reports" / "red-team.md").write_text("")
    code, out = check(r, base, "tests/codex/", "reports/red-team.md")
    assert code == 0, out


@pytest.mark.parametrize("how", ["untracked", "unstaged", "staged", "committed"])
def test_any_change_outside_scope_fails(repo, how):
    r, base = repo
    target = r / ("agent/evil.py" if how == "untracked" else "agent/core.py")
    target.write_text("x = 2\n")
    if how in ("staged", "committed"):
        git(r, "add", ".")
    if how == "committed":
        git(r, "commit", "-q", "-m", "c")
    code, out = check(r, base, "tests/codex/")
    assert code == 1 and "SCOPE VIOLATION" in out, out


def test_exact_file_rule_does_not_allow_siblings(repo):
    r, base = repo
    (r / "reports").mkdir()
    (r / "reports" / "red-team.md.bak").write_text("")
    assert check(r, base, "reports/red-team.md")[0] == 1


def test_unknown_base_is_a_usage_error(repo):
    r, _ = repo
    assert check(r, "0" * 40, "tests/codex/")[0] == 2
