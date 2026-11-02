"""A3 pure staging and injected SCM tests; no elevation needed."""

from __future__ import annotations

import ctypes
import json
import os
import uuid
from pathlib import Path

import pytest

from sentinel.service import entry, installer
from sentinel.service.paths import STATE_CHILDREN, installed_paths
from sentinel.service.integrity import IntegrityError, check_runtime
from sentinel.service.winpipe import current_process_caller


def source_tree(root: Path) -> Path:
    root.mkdir()
    for name in ("python.exe", "pythonw.exe", "python3.dll", "python315.dll", "Lib/os.py", "DLLs/_hashlib.pyd",
                 "app/sentinel/__init__.py", "vendor/yara_x/__init__.py", "Lib/pip/bad.py",
                 "Lib/sitecustomize.py", "Lib/__pycache__/bad.pyc", "app/editable.pth", "pyvenv.cfg"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(name.encode())
    return root


def test_paths_ignore_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_HOME", "C:/hostile")
    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    assert paths.version == tmp_path / "pf/SentinelGuard/versions/v1"
    assert {p.name for p in (paths.state(name) for name in STATE_CHILDREN)} == set(STATE_CHILDREN)
    with pytest.raises(ValueError):
        installed_paths("../escape", program_files=tmp_path, program_data=tmp_path)


def test_plan_excludes_bootstrap_and_dev_files(tmp_path):
    source = source_tree(tmp_path / "source")
    names = {str(f.relative).replace("\\", "/") for f in installer.plan_runtime(source)}
    assert "python.exe" in names and "python315.dll" in names
    assert "vendor/yara_x/__init__.py" in names
    assert "Lib/pip/bad.py" not in names
    assert "Lib/sitecustomize.py" not in names
    assert "Lib/__pycache__/bad.pyc" not in names
    assert "app/editable.pth" not in names
    assert "pyvenv.cfg" not in names


def test_write_runtime_hashes_and_dll_pth(tmp_path):
    plan = installer.plan_runtime(source_tree(tmp_path / "source"))
    target = tmp_path / "version"
    hashes = installer.write_runtime(plan, target)
    assert (target / "python315._pth").read_text() == "Lib\nDLLs\napp\nvendor\n"
    assert hashes == json.loads((target / "manifest.json").read_text())["sha256"]
    installer.verify_runtime(target)
    (target / "app/sentinel/__init__.py").write_text("changed")
    with pytest.raises(installer.InstallError, match="INSTALL_INTEGRITY"):
        installer.verify_runtime(target)


class FakeScm:
    def __init__(self, elevated=True):
        self.is_elevated = elevated
        self.calls = []

    def elevated(self):
        self.calls.append(("elevated",))
        return self.is_elevated

    def create_protected_directory(self, path, sddl):
        self.calls.append(("mkdir", path, sddl))
        path.mkdir()

    def create(self, name, display, binary):
        self.calls.append(("create", name, display, binary))
        return 7

    def configure(self, service, level, value):
        self.calls.append(("config", level, type(value), ctypes.sizeof(value)))

    def security(self, service, sddl):
        self.calls.append(("security", sddl))

    def service_sid(self, name):
        self.calls.append(("sid", name))
        return "S-1-5-80-1-2-3-4-5"

    def protect_code(self, root, sddl):
        self.calls.append(("code_acl", root, sddl))

    def start(self, service):
        self.calls.append(("start", service))

    def close(self, service):
        self.calls.append(("close", service))

    def stop_delete(self, name, timeout):
        self.calls.append(("stop_delete", name, timeout))
        return "PENDING_DELETE"

    def verify_state(self, root):
        self.calls.append(("verify_state", root))

    def remove_code(self, root):
        self.calls.append(("remove_code", root))


def test_reinstall_reuses_verified_state_and_never_recreates_it(tmp_path):
    # Quarantine outlives an uninstall, so an install after it finds the state tree.
    source = source_tree(tmp_path / "source")
    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    paths.code_root.parent.mkdir()
    paths.state_root.mkdir(parents=True)
    fake = FakeScm()
    installer.install(source, "v1", scm=fake, paths=paths)
    assert ("verify_state", paths.state_root) in fake.calls
    assert paths.state_root not in {c[1] for c in fake.calls if c[0] == "mkdir"}


def test_uninstall_stops_first_and_keeps_state(tmp_path):
    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    fake = FakeScm()
    assert installer.uninstall(scm=fake, paths=paths) == "PENDING_DELETE"
    assert [c[0] for c in fake.calls] == ["elevated", "stop_delete", "remove_code"]
    assert fake.calls[-1][1] == paths.code_root


def test_snapshot_is_installable_and_has_no_checkout_in_it(tmp_path):
    digest = installer.snapshot_runtime(tmp_path / "snapshot")
    assert len(digest) == 64
    plan = installer.plan_runtime(tmp_path / "snapshot")
    names = {f.relative.as_posix() for f in plan}
    assert "python.exe" in names and "app/sentinel/service/entry.py" in names
    assert not any("site-packages" in name or name.endswith((".pth", ".pyc")) for name in names)
    with pytest.raises(installer.InstallError, match="INSTALL_PATH_OCCUPIED"):
        installer.snapshot_runtime(tmp_path / "snapshot")


def test_install_stages_then_configures_and_starts(tmp_path):
    source = source_tree(tmp_path / "source")
    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    paths.code_root.parent.mkdir()
    paths.state_root.parent.mkdir()
    fake = FakeScm()
    installer.install(source, "v1", scm=fake, paths=paths)
    calls = fake.calls
    create = next(i for i, c in enumerate(calls) if c[0] == "create")
    assert calls[create][3] == f'"{paths.python}" -I -B -m sentinel.service.entry'
    assert (paths.version / "manifest.json").is_file()
    assert [c[1] for c in calls if c[0] == "config"] == list(range(1, 8))
    assert ("security", installer.SERVICE_SDDL) in calls
    assert calls[-2:] == [("start", 7), ("close", 7)]
    assert {c[1].name for c in calls if c[0] == "mkdir"} >= set(STATE_CHILDREN)


def test_unelevated_and_dry_run_never_mutate(tmp_path, capsys):
    source = source_tree(tmp_path / "source")
    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    fake = FakeScm(False)
    installer.install(source, "v1", scm=fake, paths=paths, dry_run=True)
    assert '"files"' in capsys.readouterr().out
    assert fake.calls == []
    with pytest.raises(installer.ElevationRequired):
        installer.install(source, "v1", scm=fake, paths=paths)
    assert not paths.code_root.exists()


def test_occupied_path_is_refused_before_staging(tmp_path):
    source = source_tree(tmp_path / "source")
    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    paths.code_root.mkdir(parents=True)
    with pytest.raises(installer.InstallError, match="INSTALL_PATH_OCCUPIED"):
        installer.install(source, "v1", scm=FakeScm(), paths=paths)


def test_classification_does_not_follow_reparse(tmp_path):
    class Stat:
        st_file_attributes = 0x400
    class Fs:
        def lstat(self, path):
            return Stat()
    assert installer.classify_target(Fs(), tmp_path / "x") == "reparse"
    if os.name == "nt":
        target = tmp_path / "target"
        target.mkdir()
        link = tmp_path / "junction"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            pytest.skip("creating a reparse fixture needs Developer Mode")
        assert installer.classify_target(os, link) == "reparse"


def test_scm_layout_and_uninstall_delegation():
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        installer.check_layout()
    fake = FakeScm()
    assert installer.uninstall(scm=fake, name="SentinelGuardTest-1") == "PENDING_DELETE"
    assert fake.calls[:2] == [("elevated",), ("stop_delete", "SentinelGuardTest-1", 30.0)]


def test_service_configuration_values_and_layout():
    values = dict(installer.service_config())
    assert installer.SERVICE_ACCESS == 0x70037
    assert installer.SERVICE_SDDL == "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0002008D;;;IU)"
    assert values[2].dwResetPeriod == 86400
    assert [(values[2].lpsaActions[i].Type, values[2].lpsaActions[i].Delay) for i in range(3)] == [
        (1, 5000), (1, 30000), (0, 0)]
    assert values[3].fDelayedAutostart == 0
    assert values[4].fFailureActionsOnNonCrashFailures == 0
    assert values[5].dwServiceSidType == 1
    assert values[7].dwPreshutdownTimeout == 40000
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert {cls.__name__: ctypes.sizeof(cls) for cls in installer.CONFIG_SIZES_X64} == {
            cls.__name__: n for cls, n in installer.CONFIG_SIZES_X64.items()}


def test_registration_failure_requests_cleanup(tmp_path):
    source = source_tree(tmp_path / "source")
    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    paths.code_root.parent.mkdir()
    paths.state_root.parent.mkdir()
    class Broken(FakeScm):
        def configure(self, service, level, value):
            super().configure(service, level, value)
            raise OSError("configuration failed")
    fake = Broken()
    with pytest.raises(OSError):
        installer.install(source, "v1", scm=fake, paths=paths)
    assert ("stop_delete", "SentinelGuard", 5.0) in fake.calls
    assert ("remove_code", paths.code_root) in fake.calls
    assert fake.calls[-1] == ("close", 7)


def test_a_failure_before_the_service_exists_also_clears_the_code_tree(tmp_path, monkeypatch):
    source = source_tree(tmp_path / "source")
    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    paths.code_root.parent.mkdir()
    paths.state_root.parent.mkdir()

    def broken(version):
        raise installer.InstallError("INSTALL_INTEGRITY", "planted")

    monkeypatch.setattr(installer, "verify_runtime", broken)
    fake = FakeScm()
    with pytest.raises(installer.InstallError):
        installer.install(source, "v1", scm=fake, paths=paths)
    assert fake.calls[-1] == ("remove_code", paths.code_root)
    assert not any(c[0] in ("create", "stop_delete") for c in fake.calls)


@pytest.mark.skipif(os.name != "nt", reason="the real service manager")
def test_a_service_that_is_gone_reports_absent_so_uninstall_can_finish():
    name = "SentinelGuardTest-" + uuid.uuid4().hex
    assert installer.WindowsScm().stop_delete(name, 1.0) == "ABSENT"


def test_only_a_registration_inside_the_protected_install_names_a_version(tmp_path, monkeypatch):
    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    paths.version.mkdir(parents=True)
    monkeypatch.setattr(installer, "installed_paths", lambda version: paths)
    good = f'"{paths.python}" -I -B -m sentinel.service.entry'
    assert installer.version_from_binary(good) == paths.version
    elsewhere = tmp_path / "elsewhere" / "versions" / "v1"
    elsewhere.mkdir(parents=True)
    for bad in (None, "", good.replace(" -I -B", ""), good + " --extra", good.replace("python.exe", "pythonw.exe"),
                good.replace(str(paths.version), str(elsewhere)), good.replace('"', "")):
        assert installer.version_from_binary(bad) is None


@pytest.mark.skipif(os.name != "nt", reason="the real service manager")
def test_an_unregistered_service_has_no_binary_and_no_version():
    name = "SentinelGuardTest-" + uuid.uuid4().hex
    assert installer.WindowsScm().binary(name) is None
    assert installer.registered_version(name) is None


@pytest.mark.skipif(os.name != "nt", reason="a real token")
def test_a_privilege_the_token_lacks_is_reported_not_assumed():
    installer.enable_privilege("SeChangeNotifyPrivilege")
    if installer.WindowsScm().elevated():
        pytest.skip("this token holds SeRestorePrivilege")
    with pytest.raises(OSError) as caught:
        installer.enable_privilege("SeRestorePrivilege")
    assert caught.value.errno == 1300


@pytest.mark.skipif(os.name != "nt", reason="real security descriptors")
def test_what_windows_reads_back_is_what_the_install_checks_for(tmp_path, monkeypatch):
    # The real calls and the real text; only the owner differs, which needs elevation.
    me = current_process_caller().sid
    monkeypatch.setattr(installer, "verify_path_acl", lambda *a, **k: None)
    monkeypatch.setattr(installer, "enable_privilege", lambda name: None)
    aces = f"(A;OICI;FA;;;SY)(A;OICI;FA;;;{me})(A;OICI;FRFX;;;BU)"
    expected = "O:SYG:SYD:P" + aces
    written = f"O:{me}G:BUD:P" + aces
    scm = installer.WindowsScm()
    folder = tmp_path / "folder"
    scm.create_protected_directory(folder, written)
    item = folder / "item.bin"
    item.write_bytes(b"x")
    scm._secure_path(item, written, directory=False)

    def as_installed(path):
        return installer.read_sddl(path).replace(f"O:{me}G:BU", "O:SYG:SY")

    assert installer.acl_matches(as_installed(folder), expected, directory=True)
    assert installer.acl_matches(as_installed(item), expected, directory=False)
    assert not installer.acl_matches(as_installed(item), expected + "(A;;FA;;;WD)", directory=False)
    assert not installer.acl_matches(installer.read_sddl(item), expected, directory=False)


def test_protected_acl_refuses_what_is_not_exactly_expected():
    expected = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BU)"
    good = "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)"
    assert installer.acl_matches(good, expected, directory=True)
    assert not installer.acl_matches(good.replace("D:PAI", "D:AI"), expected, directory=True)
    assert not installer.acl_matches(good.replace("0x1200a9", "0x1301bf"), expected, directory=True)
    assert not installer.acl_matches(good + "(A;OICI;FA;;;WD)", expected, directory=True)
    assert not installer.acl_matches(good.replace("(A;OICI;FA", "(A;;FA"), expected, directory=True)


def test_a_state_file_may_be_owned_by_either_trusted_owner_and_no_one_else():
    both = "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
    for good in ("O:SYG:SY" + both, "O:BAG:SY" + both, "O:SYG:SYD:AI(A;OICIID;0x1f01ff;;;BA)(A;OICIID;FA;;;SY)"):
        assert installer.acl_matches(good, "", directory=False, inherited=True)
    for bad in ("O:S-1-5-21-1-2-3-1001G:SY" + both, "O:SYG:SYD:AI(A;ID;FA;;;SY)",
                "O:SYG:SY" + both + "(A;ID;FA;;;BU)", "O:SYG:SYD:AI(A;ID;FR;;;SY)(A;ID;FA;;;BA)",
                "O:SYG:SYD:AI(D;ID;FA;;;SY)(A;ID;FA;;;BA)", "O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;WD)"):
        assert not installer.acl_matches(bad, "", directory=False, inherited=True)


def test_a_failed_start_leaves_its_reason_in_the_log(monkeypatch, tmp_path, caplog):
    paths = installed_paths("v1", program_files=tmp_path / "pf", program_data=tmp_path / "pd")
    paths.state("journal").mkdir(parents=True)
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    monkeypatch.setattr(entry, "active_version", lambda: paths.version)
    monkeypatch.setattr(entry, "installed_paths", lambda version: paths)

    def refused(factory, version):
        raise IntegrityError("STATE_ACL_UNSAFE", "planted")

    monkeypatch.setattr(entry, "run", refused)
    with pytest.raises(IntegrityError):
        entry.main()
    assert "service could not start" in caplog.text and "planted" in caplog.text


def test_startup_rejects_import_path_and_bytecode_drift(tmp_path):
    version = tmp_path / "version"
    (version / "app/sentinel").mkdir(parents=True)
    (version / "python.exe").write_bytes(b"synthetic")
    (version / "python315.dll").write_bytes(b"synthetic")
    module = type("Module", (), {"__file__": str(version / "app/sentinel/__init__.py")})()
    (version / "app/sentinel/__init__.py").write_text("")
    good_path = [str(version / n) for n in ("Lib", "DLLs", "app", "vendor")]
    with pytest.raises(IntegrityError, match="INSTALL_INTEGRITY"):
        check_runtime(version, path=good_path + [str(tmp_path)], isolated=1, dont_write=True,
                      modules={"sentinel": module}, executable=str(version / "python.exe"), prefix=str(version))
    with pytest.raises(IntegrityError, match="INSTALL_INTEGRITY"):
        check_runtime(version, path=good_path, isolated=0, dont_write=True,
                      modules={"sentinel": module}, executable=str(version / "python.exe"), prefix=str(version))
