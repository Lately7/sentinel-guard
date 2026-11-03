"""Status CLI tests; all service and SCM calls are replaced with fakes."""

from __future__ import annotations

import ctypes
import json
from ctypes import wintypes
from pathlib import Path

import pytest

from sentinel import __main__ as cli
from sentinel.service import client, installer


@pytest.fixture
def fake_service(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    state: dict[str, object] = {"binary": "registered command", "version": Path("v1"),
                                "scm_state": 4, "reply": {"worker_failure": ""}}

    class Scm:
        def binary(self, name: str) -> str | None:
            assert name == "SentinelGuard"
            return state["binary"]  # type: ignore[return-value]

    class Client:
        def __enter__(self) -> Client:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def request(self, op: str) -> dict[str, object]:
            assert op == "status"
            reply = state["reply"]
            if isinstance(reply, Exception):
                raise reply
            return reply  # type: ignore[return-value]

    monkeypatch.setattr(installer, "WindowsScm", Scm)
    monkeypatch.setattr(installer, "registered_version", lambda: state["version"])
    monkeypatch.setattr(cli, "_service_state", lambda scm: state["scm_state"])
    monkeypatch.setattr(client, "ServiceClient", Client)
    return state


@pytest.mark.parametrize(("binary", "scm_state", "reply", "message"), [
    (None, 4, {"worker_failure": ""}, "chưa được cài đặt"),
    ("registered command", 1, {"worker_failure": ""}, "đã dừng"),
    ("registered command", 4, client.ServiceUnavailable("SERVICE_UNAVAILABLE"), "Không kết nối"),
])
def test_status_distinguishes_unavailable_states(
        fake_service: dict[str, object], capsys: pytest.CaptureFixture[str], binary: str | None,
        scm_state: int, reply: object, message: str) -> None:
    fake_service.update(binary=binary, scm_state=scm_state, reply=reply)
    assert cli.main(["service", "status"]) == 2
    assert message in capsys.readouterr().out


def test_status_shows_health_and_observation(fake_service: dict[str, object],
                                             capsys: pytest.CaptureFixture[str]) -> None:
    fake_service["reply"] = {"version": "v9", "realtime": True, "worker_failure": "",
                             "quarantined": 3, "observation": {
                                 "records": 12, "refused_paths": 2, "lookup_failed": 1,
                                 "journal_lag_bytes": 42, "largest_gap": 1.5,
                                 "slept_seconds": 7, "etw": "đang chạy", "future_key": 99}}
    assert cli.main(["service", "status"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "quét hoạt động" in lines[0].lower()
    for value in ("v9", "3", "12", "2", "1", "42", "1.5", "7", "đang chạy"):
        assert value in "\n".join(lines[1:])
    assert "99" not in "\n".join(lines)


def test_dead_worker_is_not_reported_healthy(fake_service: dict[str, object],
                                             capsys: pytest.CaptureFixture[str]) -> None:
    fake_service["reply"] = {"version": "v1", "realtime": True,
                             "worker_failure": "Worker 5 failed"}
    assert cli.main(["service", "status"]) == 1
    assert "Worker 5 failed" in capsys.readouterr().out.splitlines()[0]


def test_old_reply_missing_fields_is_not_clean(fake_service: dict[str, object],
                                                capsys: pytest.CaptureFixture[str]) -> None:
    fake_service["reply"] = {"version": "v1", "observation": {"records": 0}}
    assert cli.main(["service", "status"]) == 1
    output = capsys.readouterr().out
    assert "chưa được báo cáo" in output.lower()
    assert "Bản ghi: 0" in output
    assert "Số đường dẫn bị từ chối: Chưa được báo cáo" in output
    assert "Tra cứu thất bại: Chưa được báo cáo" in output
    assert "Độ trễ nhật ký (byte): Chưa được báo cáo" in output
    assert "Khoảng gián đoạn lớn nhất: Chưa được báo cáo" in output
    assert "Thời gian ngủ (giây): Chưa được báo cáo" in output


def test_realtime_off_is_clear_even_when_scanning_works(fake_service: dict[str, object],
                                                        capsys: pytest.CaptureFixture[str]) -> None:
    fake_service["reply"] = {"worker_failure": "", "realtime": False}
    assert cli.main(["service", "status"]) == 0
    output = capsys.readouterr().out.splitlines()
    assert "đang tắt" in output[0]
    assert "Phiên bản: Chưa được báo cáo" in output
    assert "Bảo vệ thời gian thực: Tắt" in output


def test_json_is_unmodified_reply_with_health_exit(fake_service: dict[str, object],
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    reply = {"version": "old", "worker_failure": "lỗi", "future_key": [1, 2]}
    fake_service["reply"] = reply
    assert cli.main(["service", "status", "--json"]) == 1
    assert json.loads(capsys.readouterr().out) == reply


def test_scm_state_uses_interactive_query_right_only() -> None:
    calls: list[tuple[object, ...]] = []

    class Api:
        def OpenServiceW(self, manager: int, name: str, access: int) -> int:
            calls.append(("open", manager, name, access))
            return 20

        def QueryServiceStatusEx(self, service: int, level: int, status: object,
                                 size: int, needed: object) -> int:
            calls.append(("query", service, level))
            ctypes.cast(status, ctypes.POINTER(wintypes.DWORD))[1] = 4
            return 1

    class Scm:
        adv = Api()

        def _manager(self, access: int) -> int:
            calls.append(("manager", access))
            return 10

        def _check(self, result: int, operation: str) -> None:
            assert result == 1

        def close(self, handle: int) -> None:
            calls.append(("close", handle))

    assert cli._service_state(Scm()) == 4
    assert calls == [("manager", installer.SC_MANAGER_CONNECT),
                     ("open", 10, "SentinelGuard", 0x4), ("query", 20, 0),
                     ("close", 20), ("close", 10)]
