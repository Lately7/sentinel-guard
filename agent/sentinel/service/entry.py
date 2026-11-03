"""SCM entry for the protected, isolated runtime."""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from logging.handlers import RotatingFileHandler
from typing import Any

from .core import ServiceCore
from .integrity import IntegrityError, startup_check
from .paths import InstalledPaths, active_version, installed_paths
from .winpipe import PIPE_NAME, SERVICE_SDDL, PipeServer

log = logging.getLogger(__name__)


class ProductService:
    """Listens on the pipe; stop answers True only once the action barrier is closed."""

    def __init__(self, make_backend: Callable[[], Any], *, name: str = PIPE_NAME, sddl: str = SERVICE_SDDL) -> None:
        self.make_backend = make_backend
        self.name, self.sddl = name, sddl
        self.backend: Any = None
        self.server: PipeServer | None = None

    def start(self) -> None:
        self.backend = self.make_backend()
        # Crash recovery and the saved on/off state settle before any client is heard.
        self.backend.start()
        self.server = PipeServer(ServiceCore(self.backend), name=self.name, sddl=self.sddl)
        threading.Thread(target=self.server.serve_forever, name="pipe-server", daemon=True).start()

    def stop(self, timeout: float) -> bool:
        if self.server is not None:
            self.server.stop()
            self.server = None
        return self.backend.stop(timeout) if self.backend is not None else True


def _state_backend(paths: InstalledPaths) -> Any:
    from .backend import build

    return build(paths.state("db") / "sentinel.db")


def run(factory: Callable[[], object], version_id: str) -> None:
    paths = installed_paths(version_id)
    startup_check(paths.version, paths.state_root)
    from .host import run_as_service
    run_as_service(factory)


def main() -> None:
    version = active_version()
    if version is None:
        raise IntegrityError("INSTALL_INTEGRITY", "not running from the installed runtime")
    paths = installed_paths(version.name)
    # The service keeps its own state in the protected tree, never in a profile.
    os.environ["SENTINEL_HOME"] = str(paths.state_root)
    if not logging.getLogger().handlers:
        logging.basicConfig(handlers=[RotatingFileHandler(paths.state("journal") / "service.log",
                                                          maxBytes=5 * 1024 * 1024, backupCount=3,
                                                          encoding="utf-8")],
                            level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        run(lambda: ProductService(lambda: _state_backend(paths)), version.name)
    except Exception:
        # Failing before the dispatcher connects, SCM can show only 1067. The reason is here.
        log.exception("service could not start")
        raise


if __name__ == "__main__":
    main()
