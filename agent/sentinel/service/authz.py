"""Who may send which operation (R13b P3).

The caller's identity comes from the pipe client's token, never from the
request. Any process of the signed-in user (including malware running as that
user) gets the same token as our tray and the browser native host, so "user"
operations must never weaken protection; anything that does goes through a plan
that only a high-integrity administrator token (the UAC consent helper) can
approve.
"""

from __future__ import annotations

from dataclasses import dataclass

from .protocol import Op

INTEGRITY_LEVELS = ("untrusted", "low", "medium", "high", "system")


@dataclass(frozen=True)
class Caller:
    sid: str
    session_id: int
    integrity: str
    is_admin: bool  # an elevated token with the Administrators group enabled
    remote: bool = False

    def __post_init__(self) -> None:
        if self.integrity not in INTEGRITY_LEVELS:
            raise ValueError("unknown integrity level")

    @property
    def key(self) -> tuple[str, int]:
        return (self.sid, self.session_id)


def authorize(caller: Caller, op: Op) -> str | None:
    """None if allowed, otherwise an error code."""
    if caller.remote:
        return "FORBIDDEN"
    # Browser renderers and other sandboxed code run at low integrity; they
    # have no business talking to the service at all.
    if INTEGRITY_LEVELS.index(caller.integrity) < INTEGRITY_LEVELS.index("medium"):
        return "FORBIDDEN"
    if op.level == "elevated" and not (caller.is_admin and caller.integrity in ("high", "system")):
        return "ELEVATION_REQUIRED"
    return None
