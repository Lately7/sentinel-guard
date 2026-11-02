"""Stage a protected runtime before registering its LocalSystem service."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
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
# QUERY_CONFIG is here because configure() reads every setting back.
SERVICE_ACCESS = 0x1 | 0x2 | 0x4 | 0x10 | 0x20 | 0x10000 | 0x20000 | 0x40000
SC_MANAGER_CREATE_SERVICE = 0x2
SC_MANAGER_CONNECT = 0x1
SERVICE_QUERY_CONFIG = 0x1
_PYTHON_DLL = re.compile(r"python\d{2,}\.dll")  # python3.dll is the stable-ABI forwarder, not this
_REGISTERED = re.compile(r'"([^"]+\\python\.exe)" -I -B -m sentinel\.service\.entry\Z')
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_CANNOT_ACCEPT_CONTROLS = 1061
ERROR_SERVICE_NOT_ACTIVE = 1062
ERROR_SERVICE_MARKED_FOR_DELETE = 1072
# How Windows reads rights back, whichever way they were written.
_RIGHTS = {"FA": "0X1F01FF", "FRFX": "0X1200A9"}


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


class QUERY_SERVICE_CONFIGW(ctypes.Structure):
    _fields_ = [("dwServiceType", wintypes.DWORD), ("dwStartType", wintypes.DWORD),
                ("dwErrorControl", wintypes.DWORD), ("lpBinaryPathName", wintypes.LPWSTR),
                ("lpLoadOrderGroup", wintypes.LPWSTR), ("dwTagId", wintypes.DWORD),
                ("lpDependencies", wintypes.LPWSTR), ("lpServiceStartName", wintypes.LPWSTR),
                ("lpDisplayName", wintypes.LPWSTR)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    # One privilege, laid out flat: the LUID is the two fields after the count.
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("LowPart", wintypes.DWORD),
                ("HighPart", wintypes.LONG), ("Attributes", wintypes.DWORD)]


CONFIG_SIZES_X64 = {SC_ACTION: 8, SERVICE_FAILURE_ACTIONSW: 40, SERVICE_DESCRIPTIONW: 8,
                    SERVICE_DELAYED_AUTO_START_INFO: 4, SERVICE_FAILURE_ACTIONS_FLAG: 4,
                    SERVICE_SID_INFO: 4, SERVICE_REQUIRED_PRIVILEGES_INFOW: 8,
                    SERVICE_PRESHUTDOWN_INFO: 4}


def enable_privilege(name: str) -> None:
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
    adv.LookupPrivilegeValueW.restype = wintypes.BOOL
    adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.c_void_p, ctypes.c_void_p]
    adv.AdjustTokenPrivileges.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x20 | 0x8, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken")
    try:
        state = TOKEN_PRIVILEGES(1, 0, 0, 0x2)
        if not adv.LookupPrivilegeValueW(None, name, ctypes.byref(state, TOKEN_PRIVILEGES.LowPart.offset)):
            raise OSError(ctypes.get_last_error(), "LookupPrivilegeValueW")
        done = adv.AdjustTokenPrivileges(token, False, ctypes.byref(state), 0, None, None)
        # It returns success for a privilege the token lacks; only the last error says so.
        code = ctypes.get_last_error()
        if not done or code:
            raise OSError(code, f"AdjustTokenPrivileges {name}")
    finally:
        k32.CloseHandle(token)


def check_layout() -> None:
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise InstallError("UNSUPPORTED_ARCH", "64-bit Python required")
    for cls, size in CONFIG_SIZES_X64.items():
        if ctypes.sizeof(cls) != size:
            raise InstallError("BAD_SCM_LAYOUT", cls.__name__)


def _excluded(relative: Path) -> bool:
    parts = [p.lower() for p in relative.parts]
    name = parts[-1]
    if any(p in {"__pycache__", "site-packages", "pip", "setuptools", "wheel", "pytest", "tests", "test",
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
                (path.name.lower() in root_files or _PYTHON_DLL.fullmatch(path.name.lower())
                 or re.fullmatch(r"vcruntime[\d_]*\.dll", path.name.lower()))):
            continue
        result.append(RuntimeFile(path, relative))
    names = {str(item.relative).lower() for item in result}
    if "python.exe" not in names or "pythonw.exe" not in names or "python3.dll" not in names \
            or not any(_PYTHON_DLL.fullmatch(n) for n in names):
        raise InstallError("RUNTIME_INCOMPLETE", "Python executables and DLLs required")
    return tuple(sorted(result, key=lambda f: str(f.relative).lower()))


def write_runtime(plan: tuple[RuntimeFile, ...], target: Path) -> dict[str, str]:
    """O_EXCL avoids silently replacing a staged or attacker-created object."""
    target = Path(target)
    if target.exists() or target.is_symlink():
        raise InstallError("INSTALL_PATH_OCCUPIED", str(target))
    target.mkdir(parents=True)
    hashes: dict[str, str] = {}
    dlls = [f.relative.name for f in plan if _PYTHON_DLL.fullmatch(f.relative.name.lower())]
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
    def verify_state(self, root: Path) -> None: ...
    def remove_code(self, root: Path) -> None: ...


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
    for path in (locations.code_root, locations.code_root / "versions", locations.version):
        if classify_target(os, path) != "absent":
            raise InstallError("INSTALL_PATH_OCCUPIED", str(path))
    # Quarantine and the repair journal outlive an uninstall (R13b P9), so state
    # may already be here. It is reused only if it is still exactly what we made.
    if classify_target(os, locations.state_root) != "absent":
        manager.verify_state(locations.state_root)
    # A3 never registers a checkout path. Staging and verification finish first.
    manager.create_protected_directory(locations.code_root, STATE_SDDL)
    service = None
    try:
        manager.create_protected_directory(locations.code_root / "versions", STATE_SDDL)
        write_runtime(plan, locations.version)
        verify_runtime(locations.version)
        service = manager.create(name, "Sentinel Guard", binary_path(locations.version))
        for level, value in service_config():
            manager.configure(service, level, value)
        manager.security(service, SERVICE_SDDL)
        sid = manager.service_sid(name)
        if not re.fullmatch(r"S-1-5-80-(?:\d+-){4}\d+", sid):
            raise InstallError("INSTALL_INTEGRITY", "service SID lookup")
        if classify_target(os, locations.state_root) == "absent":
            create_state_tree(locations.state_root, manager)
        manager.protect_code(locations.code_root, CODE_SDDL.format(sid=sid))
        manager.start(service)
    except BaseException:
        if service is not None:
            try:
                manager.stop_delete(name, 5.0)
            except (OSError, InstallError):
                pass
        # Left behind, this tree would refuse the next install as occupied. It is
        # ours to remove: code_root was absent when this call began.
        try:
            manager.remove_code(locations.code_root)
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


def uninstall(*, scm: Scm | None = None, name: str = "SentinelGuard", timeout: float = 30.0,
              paths: InstalledPaths | None = None) -> str:
    manager = scm or WindowsScm()
    if not manager.elevated():
        raise ElevationRequired()
    outcome = manager.stop_delete(name, timeout)
    # Code goes only after the service stopped. State and quarantine deliberately
    # survive: they hold the user's files and the record of what was done.
    manager.remove_code((paths or installed_paths("uninstall")).code_root)
    return outcome


def version_from_binary(binary: str | None) -> Path | None:
    """The protected version a registered command line runs from, if it is one."""
    match = _REGISTERED.fullmatch(binary or "")
    if match is None:
        return None
    version = Path(match.group(1)).parent
    try:
        if version.resolve(strict=True) != installed_paths(version.name).version.resolve(strict=True):
            return None
    except (OSError, ValueError):
        return None
    return version


def registered_version(name: str = "SentinelGuard") -> Path | None:
    """Where the installed service runs from, for a process that runs elsewhere."""
    if os.name != "nt":
        return None
    try:
        return version_from_binary(WindowsScm().binary(name))
    except OSError:
        return None


def snapshot_runtime(target: Path) -> str:
    """Copy this interpreter, the package and yara_x into a folder for review.

    Protected ACLs guard the bytes after installing; they cannot vouch for them
    before (R16 "trust limit"). So install reads from a snapshot the owner has
    looked at and whose digest is printed here, never from a live checkout.
    """
    target = Path(target)
    if target.exists():
        raise InstallError("INSTALL_PATH_OCCUPIED", str(target))
    base = Path(sys.base_prefix)
    target.mkdir(parents=True)
    for path in base.iterdir():
        name = path.name.lower()
        if path.is_file() and (name in ("python.exe", "pythonw.exe", "python3.dll") or _PYTHON_DLL.fullmatch(name)
                               or re.fullmatch(r"vcruntime[\d_]*\.dll", name)):
            shutil.copy2(path, target / path.name)
    ignored = shutil.ignore_patterns("__pycache__", "*.pyc", "site-packages", "test", "tests", "tkinter",
                                     "idlelib", "ensurepip", "pip")
    for folder in ("Lib", "DLLs"):
        shutil.copytree(base / folder, target / folder, ignore=ignored)
    import sentinel

    shutil.copytree(Path(sentinel.__file__).parent, target / "app" / "sentinel", ignore=ignored)
    try:
        import yara_x
    except ImportError:
        (target / "vendor").mkdir()
    else:
        shutil.copytree(Path(yara_x.__file__).parent, target / "vendor" / "yara_x", ignore=ignored)
    digest = hashlib.sha256()
    for item in plan_runtime(target):
        digest.update(item.relative.as_posix().encode())
        digest.update(hashlib.sha256(item.source.read_bytes()).digest())
    return digest.hexdigest()


class WindowsScm:
    """Real ctypes binding; injected Scm makes ordering testable unelevated."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Windows required")
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._may_assign_owner = False
        self._bind()

    def _assign_owner(self) -> None:
        # Naming SYSTEM as owner is refused (1307) unless this is on, and an elevated
        # token holds it switched off. The service's own token lacks it, so not in __init__.
        if not self._may_assign_owner:
            enable_privilege("SeRestorePrivilege")
            self._may_assign_owner = True

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
        a.QueryServiceConfigW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD)]
        a.QueryServiceConfigW.restype = wintypes.BOOL
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

    def binary(self, name: str) -> str | None:
        """The registered command line, or None without a service. Reading it is
        open to any local user; setting it is not, which is what makes it trusted."""
        scm = self._manager(SC_MANAGER_CONNECT)
        try:
            service = self.adv.OpenServiceW(scm, name, SERVICE_QUERY_CONFIG)
            if not service:
                code = ctypes.get_last_error()
                if code == ERROR_SERVICE_DOES_NOT_EXIST:
                    return None
                raise OSError(code, "OpenServiceW")
            try:
                needed = wintypes.DWORD()
                self.adv.QueryServiceConfigW(service, None, 0, ctypes.byref(needed))
                buf = ctypes.create_string_buffer(needed.value)
                self._check(self.adv.QueryServiceConfigW(service, buf, len(buf), ctypes.byref(needed)),
                            "QueryServiceConfigW")
                return ctypes.cast(buf, ctypes.POINTER(QUERY_SERVICE_CONFIGW)).contents.lpBinaryPathName
            finally:
                self.close(service)
        finally:
            self.close(scm)

    def start(self, service: object) -> None:
        self._check(self.adv.StartServiceW(service, 0, None), "StartServiceW")

    def close(self, service: object) -> None:
        self.adv.CloseServiceHandle(service)

    def stop_delete(self, name: str, timeout: float) -> str:
        scm = self._manager(0x1)
        try:
            service = self.adv.OpenServiceW(scm, name, 0x20 | 0x4 | 0x10000)
            if not service:
                code = ctypes.get_last_error()
                # A service already gone must not stop uninstall from removing the code.
                if code == ERROR_SERVICE_DOES_NOT_EXIST:
                    return "ABSENT"
                raise OSError(code, "OpenServiceW")
            try:
                status = ctypes.create_string_buffer(64)
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
                    # A service still starting accepts no control yet, so this repeats.
                    if not self.adv.ControlService(service, 1, status) and ctypes.get_last_error() not in (
                            ERROR_SERVICE_CANNOT_ACCEPT_CONTROLS, ERROR_SERVICE_NOT_ACTIVE):
                        raise OSError(ctypes.get_last_error(), "ControlService")
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
        self._assign_owner()
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
        self._assign_owner()
        for path in walk_no_reparse(root):
            self._secure_path(path, sddl, directory=path.is_dir())

    def verify_state(self, root: Path) -> None:
        verify_protected_tree(root)

    def remove_code(self, root: Path) -> None:
        if classify_target(os, root) == "absent":
            return
        walk_no_reparse(root)  # refuses a tree with a reparse point inside
        shutil.rmtree(root)

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
            group, group_default = ctypes.c_void_p(), wintypes.BOOL()
            dacl, dacl_present, dacl_default = ctypes.c_void_p(), wintypes.BOOL(), wintypes.BOOL()
            get_owner = self.adv.GetSecurityDescriptorOwner
            get_owner.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
            get_owner.restype = wintypes.BOOL
            get_group = self.adv.GetSecurityDescriptorGroup
            get_group.argtypes = get_owner.argtypes
            get_group.restype = wintypes.BOOL
            get_dacl = self.adv.GetSecurityDescriptorDacl
            get_dacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                 ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
            get_dacl.restype = wintypes.BOOL
            self._check(get_owner(desired, ctypes.byref(owner), ctypes.byref(owner_default)), "GetSecurityDescriptorOwner")
            self._check(get_group(desired, ctypes.byref(group), ctypes.byref(group_default)), "GetSecurityDescriptorGroup")
            self._check(get_dacl(desired, ctypes.byref(dacl_present), ctypes.byref(dacl),
                                 ctypes.byref(dacl_default)), "GetSecurityDescriptorDacl")
            set_info = self.adv.SetSecurityInfo
            set_info.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                 ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            set_info.restype = wintypes.DWORD
            code = set_info(h, 1, 0x1 | 0x2 | 0x4 | 0x80000000, owner, group, dacl, None)
            if code:
                raise OSError(code, "SetSecurityInfo")
        finally:
            if h and h != wintypes.HANDLE(-1).value:
                self.k32.CloseHandle(h)
            self.k32.LocalFree(desired)
        verify_path_acl(path, sddl)


def _aces(sddl: str, *, directory: bool) -> set[str]:
    """ACEs compared as Windows keeps them: rights numeric, and no inheritance
    flags on a file, which has nothing to pass them on to."""
    aces = set()
    for ace in re.findall(r"\(([^)]*)\)", sddl):
        kind, flags, rights, *rest = ace.split(";")
        aces.add(";".join((kind, flags if directory else "", _RIGHTS.get(rights.upper(), rights.upper()), *rest)))
    return aces


def read_sddl(path: Path) -> str:
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
            return out.value or ""
        finally:
            k32.LocalFree(out)
    finally:
        k32.LocalFree(sd)


def acl_matches(actual: str, expected: str, *, directory: bool, inherited: bool = False) -> bool:
    if inherited:
        # Made by the service at run time, so owned by whichever of these two
        # LocalSystem's token defaults to; only those two can own anything here.
        if not actual.startswith(("O:SY", "O:BA")):
            return False
        aces = [ace.split(";") for ace in re.findall(r"\(([^)]*)\)", actual)]
        return (len(aces) == 2 and {ace[5] for ace in aces if len(ace) == 6} == {"SY", "BA"}
                and all(ace[0] == "A" and ace[2].upper() in ("FA", "0X1F01FF") for ace in aces))
    return (actual.startswith("O:SYG:SY") and "D:P" in actual
            and _aces(actual, directory=directory) == _aces(expected, directory=directory))


def verify_path_acl(path: Path, expected: str, *, inherited: bool = False) -> None:
    if not acl_matches(read_sddl(path), expected, directory=path.is_dir(), inherited=inherited):
        raise InstallError("STATE_ACL_UNSAFE", str(path))


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
