from __future__ import annotations

import json
from pathlib import Path

import pytest

# Built from halves at runtime so no file in the repo contains the full
# EICAR string (other antivirus products would quarantine it).
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

# Harmless marker used for on-disk detection tests via a test-only rule pack.
MARKER = b"SENTINEL-GUARD-TEST-MARKER-7f3a9c"


@pytest.fixture(autouse=True)
def sentinel_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("SENTINEL_HOME", str(home))
    return home


@pytest.fixture
def db(sentinel_home: Path):
    from sentinel.db import Database

    d = Database()
    yield d
    d.close()


@pytest.fixture
def marker_rule(sentinel_home: Path) -> Path:
    rules = sentinel_home / "rules"
    rules.mkdir(exist_ok=True)
    p = rules / "test.json"
    p.write_text(json.dumps({"rules": [{"id": "test.marker", "severity": "critical",
                                        "description": "test marker", "text": [MARKER.decode()]}]}))
    return p


@pytest.fixture
def scanner(db, marker_rule):
    from sentinel.engine.scanner import Scanner

    return Scanner(db, use_defender=False)
