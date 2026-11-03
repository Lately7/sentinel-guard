"""The elevated verifier's ordinary-token approval check, with no real pipe."""

from __future__ import annotations

import ctypes
import json
from ctypes import wintypes
from pathlib import Path

import pytest

from sentinel.service import lowclient, verify


class Probe:
    def __init__(self, *, split: bool = True, token: int | None = 42,
                 reason: str = "no shell", reply: dict | None = None,
                 failure: Exception | None = None, exit_code: int = 0) -> None:
        self.split = split
        self.token = token
        self.reason = reason
        self.reply = reply or {"result": "refused", "code": "ELEVATION_REQUIRED",
                               "integrity": "medium", "admin": False}
        self.failure = failure
        self.exit_code = exit_code
        self.closed: list[int] = []
        self.started: list[tuple[int, Path, Path]] = []
        self.shell_calls = 0

    def has_split_token(self) -> bool:
        if self.failure and isinstance(self.failure, PermissionError):
            raise self.failure
        return self.split

    def shell_token(self) -> tuple[int | None, str]:
        self.shell_calls += 1
        return self.token, self.reason

    def run(self, token: int, python: Path, cwd: Path) -> tuple[int, bytes]:
        self.started.append((token, python, cwd))
        if self.failure and not isinstance(self.failure, PermissionError):
            raise self.failure
        return self.exit_code, json.dumps(self.reply).encode()

    def close(self, token: int) -> None:
        self.closed.append(token)


VERSION = Path(r"C:\Program Files\SentinelGuard\versions\0.9")


def check(api: Probe) -> tuple[bool | None, str]:
    return verify._medium_token_cannot_approve(VERSION / "python.exe", VERSION, api=api)


def test_split_token_refused_for_elevation_passes():
    api = Probe()
    assert check(api) == (True, "ELEVATION_REQUIRED")
    assert api.started == [(42, VERSION / "python.exe", VERSION)]
    assert api.closed == [42]


def test_no_split_token_skips_without_starting_client():
    api = Probe(split=False)
    passed, detail = check(api)
    assert passed is None and "tách" in detail
    assert api.started == [] and api.closed == [] and api.shell_calls == 0


@pytest.mark.parametrize(("reason", "word"), [
    ("không có shell tương tác", "shell"),
    ("shell thuộc phiên khác", "phiên khác"),
])
def test_shell_unavailable_skips_without_starting_client(reason, word):
    api = Probe(token=None, reason=reason)
    passed, detail = check(api)
    assert passed is None and word in detail
    assert api.started == [] and api.closed == [] and api.shell_calls == 1


@pytest.mark.parametrize("api_name", ["OpenProcess", "DuplicateTokenEx"])
def test_shell_api_failure_skips_without_starting_client(api_name):
    class FailedShell(Probe):
        def shell_token(self) -> tuple[int | None, str]:
            raise OSError(f"{api_name} failed")

    api = FailedShell()
    passed, detail = check(api)
    assert passed is None and api_name in detail
    assert api.started == [] and api.closed == []


def test_a_client_approval_fails_even_with_a_throwaway_plan_id():
    api = Probe(reply={"result": "approved", "integrity": "medium", "admin": False})
    assert check(api)[0] is False
    assert api.closed == [42]


@pytest.mark.parametrize("failure", [TimeoutError("15 s"), OSError("cannot start")])
def test_timeout_and_start_failure_skip_and_close_token(failure):
    api = Probe(failure=failure)
    assert check(api)[0] is None
    assert api.closed == [42]


def test_elevation_query_failure_skips():
    api = Probe(failure=PermissionError("token unavailable"))
    assert check(api)[0] is None
    assert api.started == []


def test_native_timeout_terminates_the_client_before_reporting_timeout():
    class Kernel:
        def __init__(self) -> None:
            self.waits = iter([lowclient.WAIT_TIMEOUT, lowclient.WAIT_OBJECT_0])
            self.terminated: list[tuple[int, int]] = []

        def WaitForSingleObject(self, process: int, timeout: int) -> int:
            assert (process, timeout) in ((42, 15_000), (42, 5_000))
            return next(self.waits)

        def TerminateProcess(self, process: int, code: int) -> bool:
            self.terminated.append((process, code))
            return True

    probe = object.__new__(lowclient.WindowsProbe)
    probe.k32 = Kernel()
    with pytest.raises(TimeoutError):
        probe._wait_client(42)
    assert probe.k32.terminated == [(42, 1)]


def test_native_wait_accepts_only_a_finished_process():
    class Kernel:
        def WaitForSingleObject(self, process: int, timeout: int) -> int:
            assert (process, timeout) == (42, 15_000)
            return lowclient.WAIT_OBJECT_0

    probe = object.__new__(lowclient.WindowsProbe)
    probe.k32 = Kernel()
    assert probe._wait_client(42) is None


@pytest.mark.parametrize("split", [True, False])
def test_native_elevation_api_detects_split_token_without_querying_link(split):
    class Kernel:
        def __init__(self) -> None:
            self.closed: list[int] = []

        def GetCurrentProcess(self) -> int:
            return 1

        def CloseHandle(self, handle: wintypes.HANDLE | int) -> None:
            self.closed.append(handle.value if isinstance(handle, wintypes.HANDLE) else handle)

    class Adv:
        def OpenProcessToken(self, process: int, access: int, out: object) -> bool:
            assert (process, access) == (1, lowclient.TOKEN_QUERY)
            ctypes.cast(out, ctypes.POINTER(wintypes.HANDLE))[0] = wintypes.HANDLE(11)
            return True

        def GetTokenInformation(self, token: wintypes.HANDLE, kind: int, out: object,
                                length: int, size: object) -> bool:
            assert token.value == 11
            if kind == lowclient.TOKEN_ELEVATION_TYPE:
                ctypes.cast(out, ctypes.POINTER(wintypes.DWORD))[0] = (
                    lowclient.ELEVATION_TYPE_FULL if split else 1)
            else:
                pytest.fail("linked token must not be queried")
            return True

    probe = object.__new__(lowclient.WindowsProbe)
    probe.k32, probe.adv = Kernel(), Adv()
    assert probe.has_split_token() is split
    assert probe.k32.closed == [11]


@pytest.mark.parametrize(("stage", "shell_session", "expected_closed"), [
    ("no_shell", 7, []),
    ("other_session", 8, [22, 11]),
    ("open_process", 7, []),
    ("duplicate", 7, [33, 22, 11]),
    ("success", 7, [22, 11]),
])
def test_native_shell_token_paths(stage, shell_session, expected_closed):
    class User:
        def GetShellWindow(self) -> int:
            return 0 if stage == "no_shell" else 101

        def GetWindowThreadProcessId(self, window: int, out: object) -> int:
            assert window == 101
            ctypes.cast(out, ctypes.POINTER(wintypes.DWORD))[0] = 200
            return 1

    class Kernel:
        def __init__(self) -> None:
            self.closed: list[int] = []

        def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:
            assert (access, inherit, pid) == (lowclient.PROCESS_QUERY_LIMITED_INFORMATION, False, 200)
            return 0 if stage == "open_process" else 11

        def GetCurrentProcessId(self) -> int:
            return 100

        def ProcessIdToSessionId(self, pid: int, out: object) -> bool:
            assert pid == 100
            ctypes.cast(out, ctypes.POINTER(wintypes.DWORD))[0] = 7
            return True

        def CloseHandle(self, handle: wintypes.HANDLE | int) -> None:
            self.closed.append(handle.value if isinstance(handle, wintypes.HANDLE) else handle)

    class Adv:
        def OpenProcessToken(self, process: int, access: int, out: object) -> bool:
            assert (process, access) == (11, lowclient.TOKEN_QUERY | lowclient.TOKEN_DUPLICATE)
            ctypes.cast(out, ctypes.POINTER(wintypes.HANDLE))[0] = wintypes.HANDLE(22)
            return True

        def GetTokenInformation(self, token: wintypes.HANDLE, kind: int, out: object,
                                length: int, size: object) -> bool:
            assert token.value == 22 and kind == lowclient.TOKEN_SESSION_ID
            assert length == ctypes.sizeof(wintypes.DWORD)
            ctypes.cast(out, ctypes.POINTER(wintypes.DWORD))[0] = shell_session
            return True

        def DuplicateTokenEx(self, source: wintypes.HANDLE, access: int, attributes: object,
                             level: int, kind: int, out: object) -> bool:
            assert source.value == 22 and attributes is None
            assert access == (lowclient.TOKEN_QUERY | lowclient.TOKEN_DUPLICATE |
                              lowclient.TOKEN_ASSIGN_PRIMARY | lowclient.TOKEN_ADJUST_DEFAULT |
                              lowclient.TOKEN_ADJUST_SESSIONID)
            assert (level, kind) == (lowclient.SECURITY_IMPERSONATION, lowclient.TOKEN_PRIMARY)
            ctypes.cast(out, ctypes.POINTER(wintypes.HANDLE))[0] = wintypes.HANDLE(33)
            return stage != "duplicate"

    probe = object.__new__(lowclient.WindowsProbe)
    probe.user, probe.k32, probe.adv = User(), Kernel(), Adv()
    if stage in ("open_process", "duplicate"):
        with pytest.raises(OSError):
            probe.shell_token()
    else:
        token, reason = probe.shell_token()
        if stage == "success":
            assert (token, reason) == (33, "")
            probe.close(token)
            expected_closed = [22, 11, 33]
        else:
            assert token is None and ("shell" in reason if stage == "no_shell" else "phiên khác" in reason)
    assert probe.k32.closed == expected_closed


@pytest.mark.parametrize("reply", [
    {"result": "unavailable", "code": "SERVICE_UNAVAILABLE", "integrity": "medium", "admin": False},
    {"result": "refused", "code": "NOT_FOUND", "integrity": "medium", "admin": False},
    {"result": "refused", "code": "ELEVATION_REQUIRED", "integrity": "high", "admin": True},
])
def test_other_response_or_wrong_client_integrity_skips(reply):
    assert check(Probe(reply=reply))[0] is None


def test_client_exit_and_bad_json_skip():
    assert check(Probe(exit_code=1))[0] is None

    class BadJson(Probe):
        def run(self, token: int, python: Path, cwd: Path) -> tuple[int, bytes]:
            return 0, b"not JSON"

    assert check(BadJson())[0] is None


def test_child_uses_a_plan_id_that_cannot_be_generated_by_the_service():
    class Client:
        def request(self, op: str, **args: object) -> dict:
            assert op == "approve_plan"
            assert args == {"plan_id": lowclient.IMPOSSIBLE_PLAN_ID, "version": 1}
            assert len(lowclient.IMPOSSIBLE_PLAN_ID) <= 64
            assert not all(c in "0123456789abcdef" for c in lowclient.IMPOSSIBLE_PLAN_ID)
            raise lowclient.ServiceError("ELEVATION_REQUIRED")

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            pass

    assert lowclient.ask(Client) == {"result": "refused", "code": "ELEVATION_REQUIRED"}


@pytest.mark.parametrize(("response", "expected"), [
    (lowclient.ServiceUnavailable("SERVICE_UNAVAILABLE"),
     {"result": "unavailable", "code": "SERVICE_UNAVAILABLE"}),
    (None, {"result": "approved"}),
])
def test_child_reports_pipe_failure_or_approval_without_acting(response, expected):
    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def request(self, op: str, **args: object) -> dict:
            assert op == "approve_plan" and args["plan_id"] == lowclient.IMPOSSIBLE_PLAN_ID
            if response is not None:
                raise response
            return {}

    assert lowclient.ask(Client) == expected
