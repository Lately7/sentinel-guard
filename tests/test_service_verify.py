"""`sentinel service verify`: the owner's elevated check, tested here against fakes."""

from __future__ import annotations

import pytest

from sentinel.service import verify

QC = r'''
SERVICE_NAME: SentinelGuard
        BINARY_PATH_NAME   : "C:\Program Files\SentinelGuard\versions\0.9\python.exe" -I -B -m sentinel.service.entry
        SERVICE_START_NAME : LocalSystem
'''


@pytest.mark.parametrize(("sddl", "safe"), [
    ("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0002008D;;;IU)", True),
    ("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCRPRC;;;IU)", True),
    ("D:(A;;GA;;;SY)(A;;CCLCRPWPRC;;;IU)", False),
    ("D:(A;;GA;;;SY)(A;;RPWP;;;BU)", False),
    ("D:(A;;GA;;;SY)(A;;GA;;;WD)", False),
    ("D:(A;;0x00000020;;;IU)", False),
    ("D:(A;;0x00040000;;;AU)", False),
    ("", False),
])
def test_ordinary_users_must_not_hold_a_right_that_stops_the_service(sddl, safe):
    assert verify.ordinary_users_cannot_stop(sddl) is safe


def test_the_real_install_descriptor_passes():
    from sentinel.service.installer import SERVICE_SDDL

    assert verify.ordinary_users_cannot_stop(SERVICE_SDDL)


def test_service_config_rejects_what_would_mean_a_hijacked_service():
    assert verify._config(QC, "STATE : 4 RUNNING")[0] is True
    assert verify._config(QC, "STATE : 1 STOPPED")[0] is False
    assert verify._config(QC.replace("LocalSystem", "NT AUTHORITY\\LocalService"), "RUNNING")[0] is False
    assert verify._config(QC.replace(" -I -B", ""), "RUNNING")[0] is False
    moved = QC.replace(r"C:\Program Files\SentinelGuard\versions\0.9", r"C:\Users\u\AppData\x")
    assert verify._config(moved, "RUNNING")[0] is False


def test_binary_is_read_from_the_quoted_path():
    assert verify.binary_of(QC) == r"C:\Program Files\SentinelGuard\versions\0.9\python.exe"
    assert verify.binary_of("nothing") is None


def test_status_must_not_claim_prevention():
    assert verify._observing({"observation": {"prevention": "none"}})[0] is True
    assert verify._observing({"observation": {"prevention": "full"}})[0] is False
    assert verify._observing({"observation": {"prevention": "none", "gap_access_denied": 3}})[0] is False


def test_not_checked_prints_differently_from_passed():
    assert verify.Check("a", True).line() == "PASS a"
    assert verify.Check("a", False, "why").line() == "FAIL a: why"
    assert verify.Check("a", None, "why").line() == "SKIP a: why"


def test_without_elevation_it_stops_before_touching_anything(monkeypatch):
    class Scm:
        def elevated(self) -> bool:
            return False

    monkeypatch.setattr(verify.installer, "WindowsScm", Scm)
    monkeypatch.setattr(verify, "sc", lambda *a: pytest.fail("no service call before the token check"))
    results = verify.run()
    assert [(r.name, r.passed) for r in results] == [("elevated_token", False)]


def test_a_service_still_starting_is_waited_for_not_failed(monkeypatch):
    replies = iter(["STATE : 2 START_PENDING", "STATE : 2 START_PENDING", "STATE : 4 RUNNING"])
    monkeypatch.setattr(verify, "sc", lambda *a: next(replies))
    monkeypatch.setattr(verify.time, "sleep", lambda s: None)
    assert "RUNNING" in verify._settled()


def test_a_service_that_never_finishes_starting_is_reported_as_it_is(monkeypatch):
    monkeypatch.setattr(verify, "sc", lambda *a: "STATE : 2 START_PENDING")
    monkeypatch.setattr(verify, "START_WAIT_SECONDS", 0.0)
    assert "START_PENDING" in verify._settled()


def test_the_pipe_gets_a_moment_after_running_then_the_failure_is_real(monkeypatch):
    class Late:
        def __init__(self, misses):
            self.misses = misses

        def request(self, op):
            if self.misses:
                self.misses -= 1
                raise verify.ServiceUnavailable("SERVICE_UNAVAILABLE")
            return {"protocol": 1}

    monkeypatch.setattr(verify.time, "sleep", lambda s: None)
    assert verify._hello(Late(2)) == (True, "")
    monkeypatch.setattr(verify, "PIPE_WAIT_SECONDS", 0.0)
    with pytest.raises(verify.ServiceUnavailable):
        verify._hello(Late(1))


def test_a_failed_worker_scan_prints_why_the_worker_is_down():
    class Service:
        def request(self, op, **kwargs):
            return {"scan_request": {"job_id": "j"}, "status": {"worker_failure": "exit 0xc0000142"},
                    "job_status": {"state": "done", "engines": ["motw"], "verdict": {"label": "unknown"}}}[op]

    passed, detail = verify._own_scan(Service())
    assert passed is False and "exit 0xc0000142" in detail


class Status:
    def __init__(self, *observations):
        self.observations = list(observations)

    def request(self, op):
        assert op == "status"
        return {"observation": self.observations.pop(0) if len(self.observations) > 1 else self.observations[0]}


def test_the_observer_check_waits_for_the_first_journal_tick(monkeypatch):
    monkeypatch.setattr(verify.time, "sleep", lambda s: None)
    before = {"prevention": "none"}
    after = {"prevention": "none", "records": 0, "gap_access_denied": 2}
    assert verify._observed(Status(before, before, after)) == (False, "journal denied 2 times")
    assert verify._observed(Status(before, {"prevention": "none", "records": 3}))[0] is True


def test_no_journal_tick_at_all_is_a_fail_not_a_pass(monkeypatch):
    monkeypatch.setattr(verify.time, "sleep", lambda s: None)
    monkeypatch.setattr(verify, "OBSERVE_WAIT_SECONDS", 0.0)
    assert verify._observed(Status({"prevention": "none"})) == (False, "no journal tick in time")


def test_a_stopped_service_ends_the_run_with_a_fail(monkeypatch):
    class Scm:
        def elevated(self) -> bool:
            return True

    monkeypatch.setattr(verify.installer, "WindowsScm", Scm)
    monkeypatch.setattr(verify, "sc", lambda *a: "STOPPED")
    assert verify.main() == 1
