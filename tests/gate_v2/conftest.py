"""Pure-policy tests do not need the repository's disk-backed home fixture."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def sentinel_home(monkeypatch: pytest.MonkeyPatch) -> Path:
    home = Path(__file__).parent
    monkeypatch.setenv("SENTINEL_HOME", str(home))
    return home
