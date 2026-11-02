"""SCM entry for the protected, isolated runtime."""

from __future__ import annotations

from collections.abc import Callable

from .integrity import IntegrityError, startup_check
from .paths import installed_paths


def run(factory: Callable[[], object], version_id: str) -> None:
    paths = installed_paths(version_id)
    startup_check(paths.version, paths.state_root)
    from .host import run_as_service
    run_as_service(factory)


def main() -> None:
    # M7 supplies a backend factory; fail rather than start an empty service.
    raise IntegrityError("INSTALL_INTEGRITY", "service backend is not wired")


if __name__ == "__main__":
    main()
