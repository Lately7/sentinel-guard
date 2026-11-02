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


def test_a_stopped_service_ends_the_run_with_a_fail(monkeypatch):
    class Scm:
        def elevated(self) -> bool:
            return True

    monkeypatch.setattr(verify.installer, "WindowsScm", Scm)
    monkeypatch.setattr(verify, "sc", lambda *a: "STOPPED")
    assert verify.main() == 1
