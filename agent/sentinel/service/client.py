"""Client side of the service protocol, shared by the tray, native host, CLI and
the UAC consent helper."""

from __future__ import annotations

import itertools
from typing import Any

from . import winpipe
from .protocol import PROTOCOL_VERSION, ProtocolError, read_frame, write_frame


class ServiceError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {message}" if message else code)


class ServiceUnavailable(ServiceError):
    """No service is listening (not installed, stopped, or still starting)."""


class WrongServer(ServiceError):
    """The pipe is answered by a process with the wrong token user."""


# Objects a LocalSystem service creates are owned by SYSTEM or, depending on its
# token's default owner, by Administrators. A same-user process can be neither.
SERVICE_OWNERS = ("S-1-5-18", "S-1-5-32-544")


class ServiceClient:
    def __init__(self, name: str = winpipe.PIPE_NAME, *, expected_sid: str | None = None) -> None:
        self.name = name
        self.expected = (expected_sid,) if expected_sid else SERVICE_OWNERS
        self._conn: winpipe.PipeStream | None = None
        self._ids = itertools.count(1)

    def __enter__(self) -> ServiceClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def request(self, op: str, **args: Any) -> dict[str, Any]:
        if self._conn is None:
            try:
                self._conn = winpipe.connect(self.name)
                if winpipe.server_pipe_owner(self._conn).upper() not in (sid.upper() for sid in self.expected):
                    # Before anything is sent: a squatter must not learn or answer requests.
                    self.close()
                    raise WrongServer("WRONG_SERVER", "pipe owner mismatch")
            except winpipe.PipeError as e:
                self.close()
                raise ServiceUnavailable("SERVICE_UNAVAILABLE", str(e)) from e
        rid = next(self._ids)
        try:
            write_frame(self._conn, {"v": PROTOCOL_VERSION, "id": rid, "op": op, "args": args})
            try:
                reply = read_frame(self._conn)
            except ProtocolError as e:
                self.close()
                raise ServiceUnavailable("SERVICE_UNAVAILABLE", str(e)) from e
        except winpipe.PipeError as e:
            self.close()
            raise ServiceUnavailable("SERVICE_UNAVAILABLE", str(e)) from e
        if reply is None:
            self.close()
            raise ServiceUnavailable("SERVICE_UNAVAILABLE", "connection closed")
        # A reply to another request means the stream is out of step; do not
        # guess which answer belongs to whom.
        if reply.get("id") not in (rid, None):
            self.close()
            raise ServiceError("BAD_REPLY", "reply id does not match")
        if not reply.get("ok"):
            err = reply.get("error") or {}
            if reply.get("id") is None:
                self.close()  # framing-level errors end the connection on the server side
            raise ServiceError(str(err.get("code", "UNKNOWN")), str(err.get("message", "")))
        result = reply.get("result")
        if not isinstance(result, dict):
            raise ServiceError("BAD_REPLY", "result is not an object")
        return result
