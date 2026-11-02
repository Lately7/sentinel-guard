"""Bounded smart and deep scan discovery (R11 §5, M8, A4).

Discovery says what exists and what could not be looked at; it never certifies
content. Every source is an injected callable, so the ledger logic is tested
without a real machine. Anything skipped lands in the report with a typed reason
(RT-024): a junction, a denied folder and a missing key are different facts.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import re
import stat
import subprocess
import time
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field

# Reasons that are facts about the machine, not coverage this scan lost.
NOT_A_GAP = {"resolved", "duplicate", "excluded_data", "missing_key", "missing"}
LONG_PATH = 248  # past this the plain Win32 path functions stop working
EXTENDED = "\\\\?\\"
MAX_TASK_XML = 16 * 1024 * 1024
MAX_WMI_OUTPUT = 1024 * 1024
PROFILE_LIST = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
STARTUP_TAIL = r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
PROFILE_VARIABLES = (("%APPDATA%", r"AppData\Roaming"), ("%LOCALAPPDATA%", r"AppData\Local"),
                     ("%TEMP%", r"AppData\Local\Temp"), ("%TMP%", r"AppData\Local\Temp"), ("%USERPROFILE%", ""))
FOLDERID_STARTUP = "{B97D20BB-F46A-4C97-BA10-5E3608430854}"
FOLDERID_COMMON_STARTUP = "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}"


@dataclass(frozen=True)
class SourceEntry:
    source: str
    entry_id: str
    path: str | None = None
    reason: str = "resolved"
    size: int = 0
    depth: int = 0


@dataclass(frozen=True)
class Target:
    path: str
    volume: int
    file_id: int
    source: str
    entry_id: str


@dataclass
class ScopeReport:
    gaps: list[SourceEntry] = field(default_factory=list)
    reasons: Counter[str] = field(default_factory=Counter)
    entries: int = 0
    queued: int = 0
    duplicates: int = 0
    bytes_seen: int = 0
    cursor: str | None = None

    @property
    def complete(self) -> bool:
        return not self.gap_count

    @property
    def gap_count(self) -> int:
        return sum(n for reason, n in self.reasons.items() if reason not in NOT_A_GAP)


Source = Callable[[], Iterable[SourceEntry]]


class Discovery(Iterator[Target]):
    def __init__(self, profile: str, sources: Mapping[str, Source], *, data_root: str | None = None,
                 max_entries: int = 2_000_000, max_bytes: int = 1 << 42, max_depth: int = 64,
                 max_seconds: float = 1800.0, max_gaps: int = 2000, cursor: str | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if profile not in {"smart", "deep"}:
            raise ValueError("profile")
        if min(max_entries, max_bytes, max_depth, max_seconds, max_gaps) <= 0:
            raise ValueError("bounds")
        self.profile, self.sources = profile, sources
        self.max_entries, self.max_bytes, self.max_depth, self.max_gaps = max_entries, max_bytes, max_depth, max_gaps
        self.deadline = clock() + max_seconds
        self.clock = clock
        self.report = ScopeReport(cursor=cursor)
        self._resume = cursor
        self.data_root = data_root
        self._data_identity: tuple[int, int] | None = None
        self._data_error = False
        if data_root:
            try:
                root = os.stat(data_root)
                self._data_identity = (root.st_dev, root.st_ino)
            except OSError:
                self._data_error = True
        self._seen: set[tuple[int, int]] = set()
        self._inside: dict[str, bool] = {}
        self._iterator = self._run()

    def __iter__(self) -> Discovery:
        return self

    def __next__(self) -> Target:
        return next(self._iterator)

    def _record(self, entry: SourceEntry) -> None:
        self.report.entries += 1
        self.report.reasons[entry.reason] += 1
        if entry.reason not in NOT_A_GAP and len(self.report.gaps) < self.max_gaps:
            self.report.gaps.append(entry)

    def _inside_data(self, path: str) -> bool:
        # By identity, not by name: the data folder has as many spellings as links
        # lead to it (RT-003, RT-007). Remembered per folder, or a deep scan would
        # stat every parent of every file.
        if self._data_identity is None:
            return False
        folder = ntpath.dirname(path)
        known = self._inside.get(folder)
        if known is None:
            known = self._folder_inside(folder)
            if len(self._inside) > 100_000:
                self._inside.clear()
            self._inside[folder] = known
        return known

    def _folder_inside(self, folder: str) -> bool:
        try:
            while True:
                item = os.stat(folder)
                if (item.st_dev, item.st_ino) == self._data_identity:
                    return True
                parent = ntpath.dirname(folder)
                if parent == folder:
                    return False
                folder = parent
        except OSError:
            return False

    def _run(self) -> Iterator[Target]:
        if self._data_error:
            # Without knowing which folder is ours the scan would flag the quarantine.
            self._record(SourceEntry("data_root", self.data_root or "", reason="identity_error"))
            return
        yield from self._pass()
        if self._resume is not None:
            # A file at the cursor that has gone away costs time, not coverage.
            self._record(SourceEntry("cursor", self._resume, reason="cursor_lost"))
            self._resume = None
            yield from self._pass()

    def _pass(self) -> Iterator[Target]:
        for source_name, source in self.sources.items():
            try:
                for entry in source():
                    if self.clock() >= self.deadline:
                        self._record(SourceEntry(source_name, entry.entry_id, reason="time_limit"))
                        return
                    if self.report.entries >= self.max_entries:
                        self._record(SourceEntry(source_name, entry.entry_id, reason="entry_limit"))
                        return
                    token = f"{source_name}\0{entry.entry_id}"
                    if self._resume is not None:
                        if token == self._resume:
                            self._resume = None
                        continue
                    self.report.cursor = token
                    target = self._admit(entry)
                    if target is not None:
                        if self.report.bytes_seen > self.max_bytes:
                            self._record(SourceEntry(entry.source, entry.entry_id, entry.path, "byte_limit"))
                            return
                        yield target
            except PermissionError:
                self._record(SourceEntry(source_name, source_name, reason="access_denied"))
            except (OSError, ValueError, TypeError, subprocess.SubprocessError):
                self._record(SourceEntry(source_name, source_name, reason="source_error"))

    def _admit(self, entry: SourceEntry) -> Target | None:
        def drop(reason: str) -> None:
            self._record(SourceEntry(entry.source, entry.entry_id, entry.path, reason, depth=entry.depth))

        if entry.depth > self.max_depth:
            drop("depth_limit")
            return None
        if entry.reason != "resolved":
            self._record(entry)
            return None
        if not entry.path:
            drop("unresolved")
            return None
        if self._inside_data(entry.path):
            drop("excluded_data")
            return None
        try:
            st = os.stat(entry.path, follow_symlinks=False)
        except PermissionError:
            drop("access_denied")
            return None
        except FileNotFoundError:
            drop("vanished")
            return None
        except (OSError, ValueError):
            drop("identity_error")
            return None
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            drop("reparse_skipped")
            return None
        if not stat.S_ISREG(st.st_mode):
            drop("not_file")
            return None
        key = (st.st_dev, st.st_ino)
        if key in self._seen:
            self.report.duplicates += 1
            drop("duplicate")
            return None
        self._seen.add(key)
        self.report.bytes_seen += st.st_size
        self._record(entry)
        self.report.queued += 1
        return Target(entry.path, *key, entry.source, entry.entry_id)


def discover(profile: str, sources: Mapping[str, Source], **bounds: object) -> Discovery:
    """An iterator of targets with a live `.report` ledger."""
    return Discovery(profile, sources, **bounds)  # type: ignore[arg-type]


def _reachable(path: str) -> str:
    return EXTENDED + path if len(path) >= LONG_PATH and not path.startswith("\\\\") else path


def walk_folder(root: str, source: str, *, max_depth: int = 64) -> Iterator[SourceEntry]:
    stack = [(root, 0)]
    while stack:
        folder, depth = stack.pop()
        try:
            scan = os.scandir(_reachable(folder))
        except FileNotFoundError:
            yield SourceEntry(source, folder, reason="missing")
            continue
        except PermissionError:
            yield SourceEntry(source, folder, reason="access_denied")
            continue
        except OSError:
            yield SourceEntry(source, folder, reason="source_error")
            continue
        with scan:
            for item in sorted(scan, key=lambda i: i.name):  # a stable order is what makes a cursor resumable
                try:
                    info = item.stat(follow_symlinks=False)
                    if item.is_symlink() or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                        yield SourceEntry(source, item.path, reason="reparse_skipped")
                    elif item.is_dir(follow_symlinks=False):
                        if depth >= max_depth:
                            yield SourceEntry(source, item.path, reason="depth_limit", depth=depth + 1)
                        else:
                            stack.append((item.path, depth + 1))
                    elif item.is_file(follow_symlinks=False):
                        yield SourceEntry(source, item.path, item.path, depth=depth)
                    else:
                        yield SourceEntry(source, item.path, reason="unsupported")
                except PermissionError:
                    yield SourceEntry(source, item.path, reason="access_denied")
                except OSError:
                    yield SourceEntry(source, item.path, reason="source_error")


def for_profile(command: str, profile: str | None) -> str:
    """Another user's command in that user's terms; this process has its own %APPDATA%."""
    if not profile:
        return command
    for name, tail in PROFILE_VARIABLES:
        command = re.sub(re.escape(name), lambda _: ntpath.join(profile, tail) if tail else profile, command,
                         flags=re.IGNORECASE)
    return command


def _command_entries(source: str, entry_id: str, command: str, profile: str | None = None) -> Iterator[SourceEntry]:
    from ..watcher import command_files

    paths = command_files(for_profile(command, profile))
    if not paths:
        yield SourceEntry(source, entry_id, reason="unresolved")
    for path in paths:
        yield SourceEntry(source, f"{entry_id}:{path}", path)


def _run_values(reg: object, hive: object, key: str, view: int, source: str, key_id: str,
                profile: str | None = None) -> Iterator[SourceEntry]:
    try:
        with reg.OpenKey(hive, key, 0, reg.KEY_READ | view) as opened:  # type: ignore[attr-defined]
            index = 0
            while True:
                try:
                    name, value, _ = reg.EnumValue(opened, index)  # type: ignore[attr-defined]
                except OSError:
                    return
                index += 1
                yield from _command_entries(source, f"{key_id}:{name}", str(value), profile)
    except FileNotFoundError:
        yield SourceEntry(source, key_id, reason="missing_key")
    except PermissionError:
        yield SourceEntry(source, key_id, reason="access_denied")
    except OSError:
        yield SourceEntry(source, key_id, reason="source_error")


def registry_entries(reg: object = None) -> Iterator[SourceEntry]:
    if reg is None:
        if os.name != "nt":
            yield SourceEntry("registry", "windows", reason="unsupported")
            return
        import winreg as reg
    from ..watcher import RUN_KEYS

    for hive_name, hive in (("HKCU", reg.HKEY_CURRENT_USER), ("HKLM", reg.HKEY_LOCAL_MACHINE)):  # type: ignore[attr-defined]
        for view_name, view in (("64", reg.KEY_WOW64_64KEY), ("32", reg.KEY_WOW64_32KEY)):  # type: ignore[attr-defined]
            for key in RUN_KEYS:
                yield from _run_values(reg, hive, key, view, "registry", f"{hive_name}:{view_name}:{key}")


def task_actions(xml_text: str) -> Iterator[SourceEntry]:
    """Executable actions from `schtasks /query /xml ONE`."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        yield SourceEntry("task", "xml", reason="source_error")
        return
    for index, task in enumerate(item for item in root if item.tag.rsplit("}", 1)[-1] == "Task"):
        uri = next((e.text for e in task.iter() if e.tag.rsplit("}", 1)[-1] == "URI" and e.text), None)
        name = uri or f"task-{index}"
        runs = 0
        for action in task.iter():
            if action.tag.rsplit("}", 1)[-1] != "Exec":
                continue
            parts = {child.tag.rsplit("}", 1)[-1]: (child.text or "") for child in action}
            command = parts.get("Command", "").strip()
            if command:
                runs += 1
                if " " in command and not command.startswith('"'):
                    command = f'"{command}"'
                yield from _command_entries("task", name, f"{command} {parts.get('Arguments', '')}")
        if not runs:
            yield SourceEntry("task", name, reason="no_executable_action")


def scheduled_tasks(*, system_root: str | None = None,
                    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run) -> Iterator[SourceEntry]:
    exe = ntpath.join(system_root or _system_root(), "System32", "schtasks.exe")
    try:
        result = run([exe, "/query", "/xml", "ONE"], capture_output=True, timeout=30, check=False)
    except subprocess.TimeoutExpired:
        yield SourceEntry("task", "schtasks", reason="timed_out")
        return
    if result.returncode:
        yield SourceEntry("task", "schtasks", reason="access_denied")
    elif len(result.stdout) > MAX_TASK_XML:
        yield SourceEntry("task", "schtasks", reason="byte_limit")
    else:
        # schtasks writes the console code page and declares no encoding.
        yield from task_actions(result.stdout.decode("oem" if os.name == "nt" else "utf-8", "replace"))


def _system_root() -> str:
    return os.environ.get("SystemRoot", r"C:\Windows")


def fixed_drives() -> Iterator[str]:
    if os.name != "nt":
        return
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    mask = kernel.GetLogicalDrives()
    for n in range(26):
        root = f"{chr(65 + n)}:\\"
        if mask & (1 << n) and kernel.GetDriveTypeW(root) == 3:
            yield root


def process_images() -> Iterator[SourceEntry]:
    from ..service.procwatch import windows_resolve, windows_snapshot

    try:
        snapshot = windows_snapshot()
    except OSError:
        yield SourceEntry("process", "snapshot", reason="source_error")
        return
    for pid in snapshot.denied:
        yield SourceEntry("process", str(pid), reason="access_denied")
    for key in snapshot.keys:
        entry_id = f"{key.pid}:{key.creation_time}"
        try:
            path, _ = windows_resolve(key)
            yield SourceEntry("process", entry_id, path)
        except ProcessLookupError:
            yield SourceEntry("process", entry_id, reason="vanished")
        except PermissionError:
            yield SourceEntry("process", entry_id, reason="access_denied")
        except OSError:
            yield SourceEntry("process", entry_id, reason="image_error")


def other_user_run_entries(reg: object = None) -> Iterator[SourceEntry]:
    """Run keys of every profile; an unloaded hive is reported, not passed over."""
    if reg is None:
        if os.name != "nt":
            yield SourceEntry("hku", "windows", reason="unsupported")
            return
        import winreg as reg
    from ..watcher import RUN_KEYS

    for sid, profile in _profiles(reg):
        try:
            reg.CloseKey(reg.OpenKey(reg.HKEY_USERS, sid))  # type: ignore[attr-defined]
        except FileNotFoundError:
            yield SourceEntry("hku", sid, reason="hive_not_loaded")
            continue
        except PermissionError:
            yield SourceEntry("hku", sid, reason="access_denied")
            continue
        except OSError:
            yield SourceEntry("hku", sid, reason="source_error")
            continue
        for key in RUN_KEYS:
            for view_name, view in (("64", reg.KEY_WOW64_64KEY), ("32", reg.KEY_WOW64_32KEY)):  # type: ignore[attr-defined]
                yield from _run_values(reg, reg.HKEY_USERS, f"{sid}\\{key}", view, "hku",  # type: ignore[attr-defined]
                                       f"{sid}:{view_name}:{key}", profile)


def _profiles(reg: object) -> Iterator[tuple[str, str]]:
    with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, PROFILE_LIST, 0, reg.KEY_READ) as parent:  # type: ignore[attr-defined]
        index = 0
        while True:
            try:
                sid = reg.EnumKey(parent, index)  # type: ignore[attr-defined]
            except OSError:
                return
            index += 1
            if not sid.startswith("S-1-5-21-"):
                continue  # the system accounts' profiles hold no user autostart
            try:
                with reg.OpenKey(parent, sid, 0, reg.KEY_READ) as key:  # type: ignore[attr-defined]
                    path, _ = reg.QueryValueEx(key, "ProfileImagePath")  # type: ignore[attr-defined]
            except OSError:
                continue
            yield sid, os.path.expandvars(str(path))


def profile_startups(reg: object = None) -> Iterator[SourceEntry]:
    if reg is None:
        if os.name != "nt":
            return
        import winreg as reg
    for _, profile in _profiles(reg):
        yield from walk_folder(ntpath.join(profile, STARTUP_TAIL), "user_startup")


def image_path(value: str, system_root: str) -> str:
    """A service ImagePath as a Win32 path; the SCM accepts forms nothing else does."""
    text = value.strip()
    if text.startswith("\\??\\"):
        text = text[4:]
    lowered = text.lower()
    if lowered.startswith("\\systemroot\\"):
        return ntpath.join(system_root, text[len("\\systemroot\\"):])
    if lowered.startswith(("system32\\", "syswow64\\")):
        return ntpath.join(system_root, text)
    return text


def service_images(reg: object = None, *, system_root: str | None = None) -> Iterator[SourceEntry]:
    if reg is None:
        if os.name != "nt":
            yield SourceEntry("service", "windows", reason="unsupported")
            return
        import winreg as reg
    root = r"SYSTEM\CurrentControlSet\Services"
    base = system_root or _system_root()
    try:
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, root, 0, reg.KEY_READ) as parent:  # type: ignore[attr-defined]
            index = 0
            while True:
                try:
                    name = reg.EnumKey(parent, index)  # type: ignore[attr-defined]
                except OSError:
                    return
                index += 1
                try:
                    with reg.OpenKey(parent, name, 0, reg.KEY_READ) as key:  # type: ignore[attr-defined]
                        value, _ = reg.QueryValueEx(key, "ImagePath")  # type: ignore[attr-defined]
                except FileNotFoundError:
                    continue  # a key without an image is not a service
                except PermissionError:
                    yield SourceEntry("service", name, reason="access_denied")
                    continue
                yield from _command_entries("service", name, image_path(str(value), base))
                # A shared svchost service runs this DLL; ImagePath only names svchost.
                try:
                    with reg.OpenKey(parent, name + r"\Parameters", 0, reg.KEY_READ) as key:  # type: ignore[attr-defined]
                        dll, _ = reg.QueryValueEx(key, "ServiceDll")  # type: ignore[attr-defined]
                    yield from _command_entries("service", f"{name}:dll", f'"{image_path(str(dll), base)}"')
                except FileNotFoundError:
                    pass
                except PermissionError:
                    yield SourceEntry("service", f"{name}:dll", reason="access_denied")
    except PermissionError:
        yield SourceEntry("service", root, reason="access_denied")
    except OSError:
        yield SourceEntry("service", root, reason="source_error")


def _elevated() -> bool:
    try:
        return bool(ctypes.WinDLL("shell32").IsUserAnAdmin())
    except (OSError, AttributeError):
        return False


WMI_QUERY = ("$n='root/subscription';"
             "Get-CimInstance -Namespace $n -ClassName CommandLineEventConsumer | ForEach-Object {'C '+$_.CommandLineTemplate};"
             "Get-CimInstance -Namespace $n -ClassName ActiveScriptEventConsumer | ForEach-Object {'S '+$_.Name}")


def wmi_consumers(*, system_root: str | None = None, elevated: Callable[[], bool] = _elevated,
                  run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run) -> Iterator[SourceEntry]:
    # Unelevated this query answers with nothing and no error, which is
    # indistinguishable from a clean machine; so it is not asked at all.
    if not elevated():
        yield SourceEntry("wmi", "consumers", reason="needs_admin")
        return
    exe = ntpath.join(system_root or _system_root(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    try:
        result = run([exe, "-NoProfile", "-NonInteractive", "-Command", WMI_QUERY],
                     capture_output=True, timeout=30, check=False)
    except subprocess.TimeoutExpired:
        yield SourceEntry("wmi", "consumers", reason="timed_out")
        return
    if result.returncode or result.stderr.strip():
        yield SourceEntry("wmi", "consumers", reason="access_denied")
        return
    if len(result.stdout) > MAX_WMI_OUTPUT:
        yield SourceEntry("wmi", "consumers", reason="byte_limit")
        return
    for index, line in enumerate(result.stdout.decode("oem" if os.name == "nt" else "utf-8", "replace").splitlines()):
        kind, _, text = line.partition(" ")
        if kind == "C":
            yield from _command_entries("wmi", str(index), text)
        elif kind == "S":
            # The script lives in WMI, not in a file there is any way to scan.
            yield SourceEntry("wmi", f"script:{text}", reason="script_consumer")


def windows_sources(profile: str, watched: list[str], *, max_depth: int = 64) -> dict[str, Source]:
    if profile not in {"smart", "deep"}:
        raise ValueError("profile")
    from ..service.paths import known_folder

    sources: dict[str, Source] = {}
    for index, folder in enumerate(watched):
        sources[f"watched:{index}"] = lambda f=folder: walk_folder(f, "watched", max_depth=max_depth)

    def startup(folder_id: str, name: str) -> Iterator[SourceEntry]:
        try:
            yield from walk_folder(str(known_folder(folder_id)), name, max_depth=max_depth)
        except OSError:
            yield SourceEntry(name, name, reason="access_denied")

    sources["user_startup"] = lambda: startup(FOLDERID_STARTUP, "user_startup")
    sources["common_startup"] = lambda: startup(FOLDERID_COMMON_STARTUP, "common_startup")
    sources["profile_startups"] = profile_startups
    sources["registry"] = registry_entries
    sources["processes"] = process_images
    sources["tasks"] = scheduled_tasks
    sources["hku"] = other_user_run_entries
    sources["services"] = service_images
    sources["wmi"] = wmi_consumers
    if profile == "deep":
        for drive in fixed_drives():
            sources[f"drive:{drive}"] = lambda d=drive: walk_folder(d, "fixed_drive", max_depth=max_depth)
    return sources
