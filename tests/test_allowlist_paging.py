"""Trusted-site list is paged, never cut short (RT-021)."""

from __future__ import annotations

import json

from sentinel import config, nativehost
from sentinel.nativehost import Host


def test_allowlist_beyond_5000_hosts_is_served_in_pages(db, monkeypatch):
    for i in range(5003):
        db.allow_host(f"site{i:05d}.example")
    monkeypatch.setattr(nativehost, "PAGE_LIMIT", 2000)
    host = Host(db, config.Settings(use_defender=False))
    got: list[str] = []
    offset = 0
    versions = set()
    while True:
        page = host.handle({"type": "get_allowlist", "offset": offset})
        assert page["ok"] and page["total"] == 5003 and page["offset"] == offset
        versions.add(page["allow_version"])
        got += page["hosts"]
        offset += len(page["hosts"])
        if not page["hosts"] or offset >= page["total"]:
            break
    assert len(versions) == 1
    assert got == sorted(f"site{i:05d}.example" for i in range(5003))


def test_allowlist_pages_stay_under_the_message_size_limit(db, monkeypatch):
    for i in range(300):
        db.allow_host(f"{'a' * 200}{i:04d}.example")
    monkeypatch.setattr(nativehost, "PAGE_BYTES", 10_000)
    host = Host(db, config.Settings(use_defender=False))
    page = host.handle({"type": "get_allowlist"})
    assert 0 < len(page["hosts"]) < 300 and page["total"] == 300
    assert len(json.dumps(page).encode()) < 12_000


def test_old_callers_without_offset_get_the_first_page(db):
    db.allow_host("trusted.example")
    page = Host(db, config.Settings(use_defender=False)).handle({"type": "get_allowlist"})
    assert page["hosts"] == ["trusted.example"] and page["total"] == 1
