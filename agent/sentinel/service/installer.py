"""Stage a protected runtime before registering its LocalSystem service."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .paths import STATE_CHILDREN, InstalledPaths, installed_paths

SERVICE_SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0002008D;;;IU)"
STATE_SDDL = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
CODE_SDDL = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)(A;OICI;FRFX;;;{sid})"
SERVICE_ACCESS = 0x2 | 0x4 | 0x10 | 0x20 | 0x10000 | 0x20000 | 0x40000
SC_MANAGER_CREATE_SERVICE = 0x2
ERROR_SERVICE_MARKED_FOR_DELETE = 1072


class InstallError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


class ElevationRequired(InstallError):
    def __init__(self) -> None:
        super().__init__("ELEVATION_REQUIRED")


class SC_ACTION(ctypes.Structure):
    _fields_ = [("Type", wintypes.DWORD), ("Delay", wintypes.DWORD)]


class SERVICE_FAILURE_ACTIONSW(ctypes.Structure):
    _fields_ = [("dwResetPeriod", wintypes.DWORD), ("lpRebootMsg", wintypes.LPWSTR),
                ("lpCommand", wintypes.LPWSTR), ("cActions", wintypes.DWORD),
                ("lpsaActions", ctypes.POINTER(SC_ACTION))]


class SERVICE_DESCRIPTIONW(ctypes.Structure):
    _fields_ = [("lpDescription", wintypes.LPWSTR)]


class SERVICE_DELAYED_AUTO_START_INFO(ctypes.Structure):
    _fields_ = [("fDelayedAutostart", wintypes.BOOL)]


class SERVICE_FAILURE_ACTIONS_FLAG(ctypes.Structure):
    _fields_ = [("fFailureActionsOnNonCrashFailures", wintypes.BOOL)]


class SERVICE_SID_INFO(ctypes.Structure):
    _fields_ = [("dwServiceSidType", wintypes.DWORD)]


class SERVICE_REQUIRED_PRIVILEGES_INFOW(ctypes.Structure):
    _fields_ = [("pmszRequiredPrivileges", ctypes.c_void_p)]


class SERVICE_PRESHUTDOWN_INFO(ctypes.Structure):
    _fields_ = [("dwPreshutdownTimeout", wintypes.DWORD)]


CONFIG_SIZES_X64 = {SC_ACTION: 8, SERVICE_FAILURE_ACTIONSW: 40, SERVICE_DESCRIPTIONW: 8,
                    SERVICE_DELAYED_AUTO_START_INFO: 4, SERVICE_FAILURE_ACTIONS_FLAG: 4,
                    SERVICE_SID_INFO: 4, SERVICE_REQUIRED_PRIVILEGES_INFOW: 8,
                    SERVICE_PRESHUTDOWN_INFO: 4}


def check_layout() -> None:
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise InstallError("UNSUPPORTED_ARCH", "64-bit Python required")
    for cls, size in CONFIG_SIZES_X64.items():
        if ctypes.sizeof(cls) != size:
            raise InstallError("BAD_SCM_LAYOUT", cls.__name__)


def _excluded(relative: Path) -> bool:
    parts = [p.lower() for p in relative.parts]
    name = parts[-1]
    if any(p in {"__pycache__", "pip", "setuptools", "wheel", "pytest", "tests", "test",
                 "include", "scripts", "idlelib", "tkinter", "ensurepip"} for p in parts):
        return True
    return (name in {"pyvenv.cfg", "sitecustomize.py", "usercustomize.py"}
            or name.startswith("__editable__") or name.endswith((".pth", ".egg-link", ".pyc")))


@dataclass(frozen=True)
class RuntimeFile:
    source: Path
    relative: Path


def plan_runtime(source: Path) -> tuple[RuntimeFile, ...]:
    """Source is a reviewed snapshot with Lib, DLLs, app and selected vendor."""
    source = Path(source).resolve()
    allowed = {"Lib", "DLLs", "app", "vendor"}
    root_files = {"python.exe", "pythonw.exe", "python3.dll"}
    result: list[RuntimeFile] = []
    for path in walk_no_reparse(source):
        if path == source:
            continue
        relative = path.relative_to(source)
        if _excluded(relative):
            continue
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise InstallError("INSTALL_PATH_OCCUPIED", str(relative))
        if not path.is_file():
            continue
        if relative.parts[0] not in allowed and not (len(relative.parts) == 1 and
                (path.name.lower() in root_files or re.fullmatch(r"python\d+\.dll|vcruntime\d*\.dll", path.name.lower()))):
            continue
        result.append(RuntimeFile(path, relative))
    names = {str(item.relative).lower() for item in result}
    if "python.exe" not in names or "pythonw.exe" not in names or "python3.dll" not in names \
            or not any(re.fullmatch(r"python\d+\.dll", n) for n in names):
        raise InstallError("RUNTIME_INCOMPLETE", "Python executables and DLLs required")
    return tuple(sorted(result, key=lambda f: str(f.relative).lower()))


def write_runtime(plan: tuple[RuntimeFile, ...], target: Path) -> dict[str, str]:
    """O_EXCL avoids silently replacing a staged or attacker-created object."""
    target = Path(target)
    if target.exists() or target.is_symlink():
        raise InstallError("INSTALL_PATH_OCCUPIED", str(target))
    target.mkdir(parents=True)
    hashes: dict[str, str] = {}
    dlls = [f.relative.name for f in plan if re.fullmatch(r"python\d+\.dll", f.relative.name.lower())]
    if len(dlls) != 1:
        raise InstallError("RUNTIME_INCOMPLETE", "one versioned Python DLL required")
    for item in plan:
        dest = target / item.relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_symlink() or dest.exists():
            raise InstallError("INSTALL_PATH_OCCUPIED", str(dest))
        digest = hashlib.sha256()
        with item.source.open("rb") as src, dest.open("xb") as dst:
            while block := src.read(1024 * 1024):
                dst.write(block)
                digest.update(block)
        hashes[item.relative.as_posix()] = digest.hexdigest()
    pth = target / (Path(dlls[0]).stem + "._pth")
    body = b"Lib\nDLLs\napp\nvendor\n"
    with pth.open("xb") as out:
        out.write(body)
    hashes[pth.name] = hashlib.sha256(body).hexdigest()
    manifest = target / "manifest.json"
    with manifest.open("x", encoding="utf-8") as out:
        json.dump({"sha256": hashes}, out, indent=2, sort_keys=True)
    return hashes


def verify_runtime(version: Path) -> None:
    try:
        manifest = json.loads((version / "manifest.json").read_text(encoding="utf-8"))["sha256"]
        for name, digest in manifest.items():
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise InstallError("INSTALL_INTEGRITY", name)
            path = version / name
            if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise InstallError("INSTALL_INTEGRITY", name)
    except (OSError, ValueError, KeyError) as exc:
        raise InstallError("INSTALL_INTEGRITY", str(exc)) from exc


def classify_target(fs: object, path: Path) -> str:
    """Fake filesystems implement lstat; lstat never follows a junction."""
    try:
        info = fs.lstat(path)  # type: ignore[attr-defined]
    except FileNotFoundError:
        return "absent"
    if getattr(info, "st_file_attributes", 0) & 0x400 or getattr(info, "st_reparse_tag", 0):
        return "reparse"
    return "occupied"


def walk_no_reparse(root: Path) -> tuple[Path, ...]:
    pending = [root]
    found = []
    while pending:
        path = pending.pop()
        if classify_target(os, path) != "occupied":
            raise InstallError("INSTALL_PATH_OCCUPIED", str(path))
        found.append(path)
        if path.is_dir():
            with os.scandir(path) as entries:
                pending.extend(Path(entry.path) for entry in entries)
    return tuple(found)


class Scm(Protocol):
    def elevated(self) -> bool: ...
    def create(self, name: str, display: str, binary: str) -> object: ...
    def configure(self, service: object, level: int, value: ctypes.Structure) -> None: ...
    def security(self, service: object, sddl: str) -> None: ...
    def service_sid(self, name: str) -> str: ...
    def start(self, service: object) -> None: ...
    def stop_delete(self, name: str, timeout: float) -> str: ...
    def close(self, service: object) -> None: ...
    def create_protected_directory(self, path: Path, sddl: str) -> None: ...
    def protect_code(self, root: Path, sddl: str) -> None: ...


def service_config() -> tuple[tuple[int, ctypes.Structure], ...]:
    actions = (SC_ACTION * 3)(SC_ACTION(1, 5000), SC_ACTION(1, 30000), SC_ACTION(0, 0))
    failure = SERVICE_FAILURE_ACTIONSW(86400, None, None, 3, actions)
    # Keep the array and multistring alive through both set and query calls.
    failure._actions = actions
    privileges = ctypes.create_unicode_buffer("SeImpersonatePrivilege\0SeIncreaseQuotaPrivilege\0\0")
    priv = SERVICE_REQUIRED_PRIVILEGES_INFOW(ctypes.cast(privileges, ctypes.c_void_p))
    priv._buffer = privileges
    return ((1, SERVICE_DESCRIPTIONW("Sentinel Guard protection service")), (2, failure),
            (3, SERVICE_DELAYED_AUTO_START_INFO(False)), (4, SERVICE_FAILURE_ACTIONS_FLAG(False)),
            (5, SERVICE_SID_INFO(1)), (6, priv), (7, SERVICE_PRESHUTDOWN_INFO(40000)))


def binary_path(version: Path) -> str:
    exe = (version / "python.exe").resolve(strict=True)
    if exe.parent != version.resolve(strict=True) or version.parent.name.lower() != "versions":
        raise InstallError("INSTALL_INTEGRITY", "executable outside protected version")
    return f'"{exe}" -I -B -m sentinel.service.entry'


def install(source: Path, version_id: str, *, scm: Scm | None = None,
            paths: InstalledPaths | None = None, name: str = "SentinelGuard", dry_run: bool = False) -> dict[str, object]:
    plan = plan_runtime(source)
    locations = paths or installed_paths(version_id)
    report: dict[str, object] = {"version": str(locations.version), "state": str(locations.state_root),
                                 "files": [str(f.relative) for f in plan]}
    if dry_run:
        print(json.dumps(report, indent=2))
        return report
    manager = scm or WindowsScm()
    if not manager.elevated():
        raise ElevationRequired()
    check_layout()
    for path in (locations.code_root, locations.code_root / "versions", locations.version, locations.state_root):
        if classify_target(os, path) != "absent":
            raise InstallError("INSTALL_PATH_OCCUPIED", str(path))
    # A3 never registers a checkout path. Staging and verification finish first.
    manager.create_protected_directory(locations.code_root, STATE_SDDL)
    manager.create_protected_directory(locations.code_root / "versions", STATE_SDDL)
    write_runtime(plan, locations.version)
    verify_runtime(locations.version)
    service = None
    try:
        service = manager.create(name, "Sentinel Guard", binary_path(locations.version))
        for level, value in service_config():
            manager.configure(service, level, value)
        manager.security(service, SERVICE_SDDL)
        sid = manager.service_sid(name)
        if not re.fullmatch(r"S-1-5-80-(?:\d+-){4}\d+", sid):
            raise InstallError("INSTALL_INTEGRITY", "service SID lookup")
        create_state_tree(locations.state_root, manager)
        manager.protect_code(locations.code_root, CODE_SDDL.format(sid=sid))
        manager.start(service)
    except BaseException:
        if service is not None:
            try:
                manager.stop_delete(name, 5.0)
            except (OSError, InstallError):
                pass
        raise
    finally:
        if service is not None:
            manager.close(service)
    return report


def create_state_tree(root: Path, manager: object) -> None:
    for path in (root, *(root / child for child in STATE_CHILDREN)):
        if classify_target(os, path) != "absent":
            raise InstallError("INSTALL_PATH_OCCUPIED", str(path))
        manager.create_protected_directory(path, STATE_SDDL)


def uninstall(*, scm: Scm | None = None, name: str = "SentinelGuard", timeout: float = 30.0) -> str:
    manager = scm or WindowsScm()
    if not manager.elevated():
        raise ElevationRequired()
    # State and quarantine deliberately survive uninstall.
    return manager.stop_delete(name, timeout)


class WindowsScm:
    """Real ctypes binding; injected Scm makes ordering testable unelevated."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Windows required")
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._bind()

    def _bind(self) -> None:
        a = self.adv
        a.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        a.OpenSCManagerW.restype = wintypes.HANDLE
        a.CreateServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
            wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR]
        a.CreateServiceW.restype = wintypes.HANDLE
        a.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
        a.OpenServiceW.restype = wintypes.HANDLE
        a.ChangeServiceConfig2W.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
        a.ChangeServiceConfig2W.restype = wintypes.BOOL
        a.QueryServiceConfig2W.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                                            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        a.QueryServiceConfig2W.restype = wintypes.BOOL
        a.CloseServiceHandle.argtypes = [wintypes.HANDLE]
        a.CloseServiceHandle.restype = wintypes.BOOL
        a.StartServiceW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
        a.StartServiceW.restype = wintypes.BOOL
        a.DeleteService.argtypes = [wintypes.HANDLE]
        a.DeleteService.restype = wintypes.BOOL
        a.ControlService.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
        a.ControlService.restype = wintypes.BOOL
        a.QueryServiceStatusEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        a.QueryServiceStatusEx.restype = wintypes.BOOL
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        a.SetServiceObjectSecurity.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
        a.SetServiceObjectSecurity.restype = wintypes.BOOL
        a.QueryServiceObjectSecurity.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                                                  wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        a.QueryServiceObjectSecurity.restype = wintypes.BOOL
        self.k32.LocalFree.argtypes = [ctypes.c_void_p]
        self.k32.LocalFree.restype = ctypes.c_void_p

    @staticmethod
    def _check(ok: object, operation: str) -> None:
        if not ok:
            raise OSError(ctypes.get_last_error(), operation)

    def elevated(self) -> bool:
        from .winpipe import current_process_caller
        caller = current_process_caller()
        return caller.is_admin and caller.integrity in ("high", "system")

    def _manager(self, access: int) -> int:
        handle = self.adv.OpenSCManagerW(None, None, access)
        self._check(handle, "OpenSCManagerW")
        return handle

    def create(self, name: str, display: str, binary: str) -> object:
        scm = self._manager(SC_MANAGER_CREATE_SERVICE)
        try:
            service = self.adv.CreateServiceW(scm, name, display, SERVICE_ACCESS, 0x10, 2, 1,
                                                binary, None, None, None, None, None)
            self._check(service, "CreateServiceW")
            return service
        finally:
            self.adv.CloseServiceHandle(scm)

    def configure(self, service: object, level: int, value: ctypes.Structure) -> None:
        self._check(self.adv.ChangeServiceConfig2W(service, level, ctypes.byref(value)),
                    "ChangeServiceConfig2W")
        needed = wintypes.DWORD()
        self.adv.QueryServiceConfig2W(service, level, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        self._check(self.adv.QueryServiceConfig2W(service, level, buf, len(buf), ctypes.byref(needed)),
                    "QueryServiceConfig2W")
        observed = ctypes.cast(buf, ctypes.POINTER(type(value))).contents
        if level in (3, 4, 5, 7):
            for field, _ in value._fields_:
                if getattr(observed, field) != getattr(value, field):
                    raise InstallError("SCM_CONFIG_MISMATCH", f"level {level}: {field}")
        elif level == 1 and observed.lpDescription != value.lpDescription:
            raise InstallError("SCM_CONFIG_MISMATCH", "description")
        elif level == 2:
            if observed.dwResetPeriod != value.dwResetPeriod or observed.cActions != value.cActions:
                raise InstallError("SCM_CONFIG_MISMATCH", "failure actions")
            expected_actions = [(value.lpsaActions[i].Type, value.lpsaActions[i].Delay)
                                for i in range(value.cActions)]
            actual_actions = [(observed.lpsaActions[i].Type, observed.lpsaActions[i].Delay)
                              for i in range(observed.cActions)]
            if actual_actions != expected_actions:
                raise InstallError("SCM_CONFIG_MISMATCH", "failure action delays")
        elif level == 6:
            expected_privileges = ["SeImpersonatePrivilege", "SeIncreaseQuotaPrivilege"]
            pointer = observed.pmszRequiredPrivileges
            if pointer is None:
                raise InstallError("SCM_CONFIG_MISMATCH", "required privileges")
            observed_privileges = []
            offset = 0
            while True:
                name = ctypes.wstring_at(pointer + offset * ctypes.sizeof(ctypes.c_wchar))
                if not name:
                    break
                observed_privileges.append(name)
                offset += len(name) + 1
            if observed_privileges != expected_privileges:
                raise InstallError("SCM_CONFIG_MISMATCH", "required privileges")

    def security(self, service: object, sddl: str) -> None:
        sd = ctypes.c_void_p()
        self._check(self.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(sd), None), "ConvertStringSecurityDescriptorToSecurityDescriptorW")
        try:
            self._check(self.adv.SetServiceObjectSecurity(service, 4, sd), "SetServiceObjectSecurity")
            needed = wintypes.DWORD()
            self.adv.QueryServiceObjectSecurity(service, 4, None, 0, ctypes.byref(needed))
            buf = ctypes.create_string_buffer(needed.value)
            self._check(self.adv.QueryServiceObjectSecurity(service, 4, buf, len(buf), ctypes.byref(needed)),
                        "QueryServiceObjectSecurity")
        finally:
            self.k32.LocalFree(sd)

    def service_sid(self, name: str) -> str:
        # Derive the service SID through Windows, never from the service name hash.
        from .winpipe import _sid_string
        account = "NT SERVICE\\" + name
        sid_size, domain_size = wintypes.DWORD(0), wintypes.DWORD(0)
        use = wintypes.DWORD()
        fn = self.adv.LookupAccountNameW
        fn.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
                       ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
                       ctypes.POINTER(wintypes.DWORD)]
        fn.restype = wintypes.BOOL
        fn(None, account, None, ctypes.byref(sid_size), None, ctypes.byref(domain_size), ctypes.byref(use))
        sid = ctypes.create_string_buffer(sid_size.value)
        domain = ctypes.create_unicode_buffer(domain_size.value)
        self._check(fn(None, account, sid, ctypes.byref(sid_size), domain,
                       ctypes.byref(domain_size), ctypes.byref(use)), "LookupAccountNameW")
        return _sid_string(ctypes.addressof(sid))

    def start(self, service: object) -> None:
        self._check(self.adv.StartServiceW(service, 0, None), "StartServiceW")

    def close(self, service: object) -> None:
        self.adv.CloseServiceHandle(service)

    def stop_delete(self, name: str, timeout: float) -> str:
        scm = self._manager(0x1)
        try:
            service = self.adv.OpenServiceW(scm, name, 0x20 | 0x4 | 0x10000)
            self._check(service, "OpenServiceW")
            try:
                status = ctypes.create_string_buffer(64)
                if not self.adv.ControlService(service, 1, status) and ctypes.get_last_error() != 1062:
                    raise OSError(ctypes.get_last_error(), "ControlService")
                deadline = time.monotonic() + timeout
                needed = wintypes.DWORD()
                while True:
                    self._check(self.adv.QueryServiceStatusEx(service, 0, status, len(status), ctypes.byref(needed)),
                                "QueryServiceStatusEx")
                    state = ctypes.cast(status, ctypes.POINTER(wintypes.DWORD))[1]
                    if state == 1:
                        break
                    if time.monotonic() >= deadline:
                        raise InstallError("STOP_TIMEOUT")
                    time.sleep(0.2)
                if not self.adv.DeleteService(service):
                    code = ctypes.get_last_error()
                    if code == ERROR_SERVICE_MARKED_FOR_DELETE:
                        return "PENDING_DELETE"
                    raise OSError(code, "DeleteService")
                return "PENDING_DELETE"
            finally:
                self.close(service)
        finally:
            self.close(scm)

    def create_protected_directory(self, path: Path, sddl: str) -> None:
        # Existing names are refused before calling CreateDirectoryW.
        if classify_target(os, path) != "absent":
            raise InstallError("INSTALL_PATH_OCCUPIED", str(path))
        sd = ctypes.c_void_p()
        self._check(self.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(sd), None), "ConvertStringSecurityDescriptorToSecurityDescriptorW")
        try:
            class SECURITY_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                            ("bInheritHandle", wintypes.BOOL)]
            sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
            fn = self.k32.CreateDirectoryW
            fn.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SECURITY_ATTRIBUTES)]
            fn.restype = wintypes.BOOL
            self._check(fn(str(path), ctypes.byref(sa)), "CreateDirectoryW")
            self._secure_path(path, sddl, directory=True)
        finally:
            self.k32.LocalFree(sd)

    def protect_code(self, root: Path, sddl: str) -> None:
        for path in walk_no_reparse(root):
            self._secure_path(path, sddl, directory=path.is_dir())

    def _secure_path(self, path: Path, sddl: str, *, directory: bool) -> None:
        # Operate on the object opened without following a reparse point.
        desired = ctypes.c_void_p()
        self._check(self.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(desired), None), "ConvertStringSecurityDescriptorToSecurityDescriptorW")
        h = None
        try:
            open_file = self.k32.CreateFileW
            open_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            open_file.restype = wintypes.HANDLE
            h = open_file(str(path), 0x20000 | 0x40000 | 0x80000, 0, None, 3,
                          0x00200000 | (0x02000000 if directory else 0), None)
            self._check(h and h != wintypes.HANDLE(-1).value, "CreateFileW(security)")
            info = self.k32.GetFileInformationByHandle
            info.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            info.restype = wintypes.BOOL
            file_info = ctypes.create_string_buffer(64)
            self._check(info(h, file_info), "GetFileInformationByHandle")
            attributes = ctypes.cast(file_info, ctypes.POINTER(wintypes.DWORD))[0]
            if attributes & 0x400:
                raise InstallError("INSTALL_PATH_OCCUPIED", str(path))
            owner, owner_default = ctypes.c_void_p(), wintypes.BOOL()
            dacl, dacl_present, dacl_default = ctypes.c_void_p(), wintypes.BOOL(), wintypes.BOOL()
            get_owner = self.adv.GetSecurityDescriptorOwner
            get_owner.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
            get_owner.restype = wintypes.BOOL
            get_dacl = self.adv.GetSecurityDescriptorDacl
            get_dacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                 ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
            get_dacl.restype = wintypes.BOOL
            self._check(get_owner(desired, ctypes.byref(owner), ctypes.byref(owner_default)), "GetSecurityDescriptorOwner")
            self._check(get_dacl(desired, ctypes.byref(dacl_present), ctypes.byref(dacl),
                                 ctypes.byref(dacl_default)), "GetSecurityDescriptorDacl")
            set_info = self.adv.SetSecurityInfo
            set_info.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                 ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            set_info.restype = wintypes.DWORD
            code = set_info(h, 1, 0x1 | 0x4 | 0x80000000, owner, None, dacl, None)
            if code:
                raise OSError(code, "SetSecurityInfo")
        finally:
            if h and h != wintypes.HANDLE(-1).value:
                self.k32.CloseHandle(h)
            self.k32.LocalFree(desired)
        verify_path_acl(path, sddl)


def verify_path_acl(path: Path, expected: str, *, inherited: bool = False) -> None:
    if os.name != "nt":
        raise InstallError("STATE_ACL_UNSAFE", "Windows required")
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get = adv.GetNamedSecurityInfoW
    get.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    get.restype = wintypes.DWORD
    sd = ctypes.c_void_p()
    code = get(str(path), 1, 0x1 | 0x2 | 0x4, None, None, None, None, ctypes.byref(sd))
    if code:
        raise InstallError("STATE_ACL_UNSAFE", f"GetNamedSecurityInfoW {code}: {path}")
    try:
        convert = adv.ConvertSecurityDescriptorToStringSecurityDescriptorW
        convert.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                            ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD)]
        convert.restype = wintypes.BOOL
        out, length = wintypes.LPWSTR(), wintypes.DWORD()
        if not convert(sd, 1, 0x1 | 0x2 | 0x4, ctypes.byref(out), ctypes.byref(length)):
            raise InstallError("STATE_ACL_UNSAFE", str(path))
        try:
            actual = out.value or ""
            if not actual.startswith("O:SYG:SY") or (not inherited and "D:P" not in actual):
                raise InstallError("STATE_ACL_UNSAFE", str(path))
            actual_aces = re.findall(r"\(([^)]*)\)", actual)
            if inherited:
                if len(actual_aces) != 2:
                    raise InstallError("STATE_ACL_UNSAFE", str(path))
                seen = set()
                for ace in actual_aces:
                    fields = ace.split(";")
                    if len(fields) != 6 or fields[0] != "A" or fields[2].upper() not in ("FA", "0X1F01FF") \
                            or fields[5] not in ("SY", "BA"):
                        raise InstallError("STATE_ACL_UNSAFE", str(path))
                    seen.add(fields[5])
                if seen != {"SY", "BA"}:
                    raise InstallError("STATE_ACL_UNSAFE", str(path))
            elif set(actual_aces) != set(re.findall(r"\(([^)]*)\)", expected)):
                raise InstallError("STATE_ACL_UNSAFE", str(path))
        finally:
            k32.LocalFree(out)
    finally:
        k32.LocalFree(sd)


def verify_protected_tree(root: Path) -> None:
    for path in (root, *(root / name for name in STATE_CHILDREN)):
        if classify_target(os, path) != "occupied" or not path.is_dir():
            raise InstallError("STATE_ACL_UNSAFE", str(path))
        verify_path_acl(path, STATE_SDDL)
    for path in walk_no_reparse(root):
        if path == root or path.parent == root and path.name in STATE_CHILDREN:
            continue
        if classify_target(os, path) != "occupied":
            raise InstallError("STATE_ACL_UNSAFE", str(path))
        info = path.lstat()
        if not path.is_dir() and not path.is_file() or (path.is_file() and info.st_nlink != 1):
            raise InstallError("STATE_ACL_UNSAFE", str(path))
        verify_path_acl(path, STATE_SDDL, inherited=True)


def verify_code_tree(root: Path, sid: str) -> None:
    expected = CODE_SDDL.format(sid=sid)
    for path in walk_no_reparse(root):
        verify_path_acl(path, expected)
