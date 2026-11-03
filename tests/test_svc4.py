"""Service log retention at the SCM entry point."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from sentinel.service import entry
from sentinel.service.paths import installed_paths


def test_service_log_rotates_with_three_utf8_backups(monkeypatch, tmp_path):
    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    journal = paths.state("journal")
    journal.mkdir(parents=True)
    monkeypatch.setattr(entry, "active_version", lambda: paths.version)
    monkeypatch.setattr(entry, "installed_paths", lambda version: paths)
    monkeypatch.setattr(entry, "run", lambda factory, version: None)
    root = logging.getLogger()
    monkeypatch.setattr(root, "handlers", [])
    monkeypatch.setattr(root, "level", root.level)
    try:
        entry.main()
        assert len(root.handlers) == 1
        handler = root.handlers[0]
        assert isinstance(handler, RotatingFileHandler)
        assert handler.baseFilename == str(journal / "service.log")
        assert (handler.maxBytes, handler.backupCount, handler.encoding) == (5 * 1024 * 1024, 3, "utf-8")
        assert handler.formatter._fmt == "%(asctime)s %(levelname)s %(name)s %(message)s"
        handler.maxBytes = 100
        for number in range(8):
            logging.getLogger("svc4").info("Vietnamese: Tiếng Việt %s %s", number, "x" * 70)
        handler.flush()
        assert sorted(p.name for p in journal.iterdir()) == [
            "service.log", "service.log.1", "service.log.2", "service.log.3"]
        assert "Tiếng Việt 7" in (journal / "service.log").read_text(encoding="utf-8")
    finally:
        for handler in root.handlers:
            handler.close()
