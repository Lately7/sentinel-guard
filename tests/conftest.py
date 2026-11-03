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
def no_installed_service(monkeypatch: pytest.MonkeyPatch) -> None:
    # A machine may have the real service. It must not answer a test, and no test
    # should hand it a path: an action lease left by one test decided the next.
    from sentinel import protection
    from sentinel.service import winpipe

    real = winpipe.connect

    def connect(name: str = winpipe.PIPE_NAME) -> winpipe.PipeStream:
        if name == winpipe.PIPE_NAME:
            raise winpipe.PipeError(2, "tests do not reach an installed service")
        return real(name)

    monkeypatch.setattr(protection, "delegate", None)
    monkeypatch.setattr(winpipe, "connect", connect)


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
