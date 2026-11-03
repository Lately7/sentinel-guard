"""Regression tests for verify waiting for the ETW start check."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from sentinel.service import verify


class StatusClient:
    def __init__(self, *states: str) -> None:
        self.states = states
        self.requests = 0

    def request(self, operation: str) -> dict[str, object]:
        assert operation == "status"
        state = self.states[min(self.requests, len(self.states) - 1)]
        self.requests += 1
        return {"observation": {"etw": state}}


def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    now = [0.0]
    monkeypatch.setattr(verify.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(verify.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    return now


@pytest.mark.parametrize("final", ["on", "no_start_events"])
def test_waits_through_checking_until_final_state(monkeypatch: pytest.MonkeyPatch, final: str) -> None:
    now = clock(monkeypatch)
    service = StatusClient("checking", "checking", final)

    result = verify._etw_settled(service)

    assert result == verify._etw({"observation": {"etw": final}})
    assert service.requests == 3
    assert now == [1.0]


def test_checking_at_deadline_is_skip_not_a_clean_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    now = clock(monkeypatch)
    service = StatusClient("checking")

    assert verify._etw_settled(service) == (None, "ETW chưa kiểm xong sau 20 giây")
    assert service.requests == 41
    assert now == [20.0]


@pytest.mark.parametrize("final", ["off", "schema_process_mismatch"])
def test_off_and_failures_return_without_waiting(monkeypatch: pytest.MonkeyPatch, final: str) -> None:
    now = clock(monkeypatch)
    service = StatusClient(final)

    assert verify._etw_settled(service) == verify._etw({"observation": {"etw": final}})
    assert service.requests == 1
    assert now == [0.0]


def test_new_etw_status_details_are_reported() -> None:
    assert verify._etw({"observation": {"etw": "on", "etw_events_parsed": 2,
                                        "etw_check_phase": "F", "etw_flush_assist": True}}) == (
        True, "đã phân tích 2 sự kiện, mất 0, qua ở pha F, cần flush mỗi giây")
    assert verify._etw({"observation": {"etw": "off", "etw_events_lost": 3,
                                        "etw_truncated": 4, "etw_query_failures": 5}}) == (
        None, "ETW tắt: off, mất 3, cắt ngắn 4, truy vấn hỏng 5")


def test_old_etw_status_strings_and_zero_counters_stay_the_same() -> None:
    assert verify._etw({"observation": {"etw": "on", "etw_events_parsed": 2}}) == (
        True, "đã phân tích 2 sự kiện, mất 0")
    assert verify._etw({"observation": {"etw": "schema_file_missing"}}) == (
        None, "ETW tắt: schema_file_missing, mất 0")
    assert verify._etw({"observation": {"etw": "off", "etw_truncated": 0,
                                        "etw_query_failures": 0}}) == (None, "ETW tắt: off, mất 0")


def test_run_uses_settled_etw_check(monkeypatch: pytest.MonkeyPatch) -> None:
    class Scm:
        def elevated(self) -> bool:
            return True

    class Service:
        def __enter__(self) -> Service:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def request(self, _operation: str) -> dict[str, object]:
            pytest.fail("run must use the settled ETW probe")

    monkeypatch.setattr(verify.installer, "WindowsScm", Scm)
    monkeypatch.setattr(verify, "sc", lambda *_args: "RUNNING")
    monkeypatch.setattr(verify, "_settled", lambda: "RUNNING")
    monkeypatch.setattr(verify, "_config", lambda *_args: (True, ""))
    monkeypatch.setattr(verify, "_version_paths", lambda _qc: SimpleNamespace(
        version="version", python="python", state_root="state"))
    monkeypatch.setattr(verify.installer, "verify_runtime", lambda _path: None)
    monkeypatch.setattr(verify.installer, "verify_protected_tree", lambda _path: None)
    monkeypatch.setattr(verify, "_imports", lambda *_args: (True, ""))
    monkeypatch.setattr(verify, "_hello", lambda _service: (True, ""))
    monkeypatch.setattr(verify, "_refuses_unknown", lambda _service: (True, ""))
    monkeypatch.setattr(verify, "_own_scan", lambda _service: (True, ""))
    monkeypatch.setattr(verify, "_observed", lambda _service: (True, ""))
    monkeypatch.setattr(verify, "_etw_settled", lambda _service: (None, "settled"))

    etw_check = next(check for check in verify.run(client=Service) if check.name == "etw")
    assert (etw_check.passed, etw_check.detail) == (None, "settled")
