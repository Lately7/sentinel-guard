"""Acting on a file through an open handle instead of its name.

A name can be re-pointed between any two calls. A same-user process that swaps a
parent folder for a junction after the scan would otherwise make the service,
running as LocalSystem, delete or write a file of the attacker's choosing, so
every step after the open works on the object the handle already holds.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import stat
import struct
from ctypes import wintypes
from typing import BinaryIO

from . import identity

GENERIC_READ, GENERIC_WRITE, DELETE = 0x80000000, 0x40000000, 0x00010000
FILE_WRITE_ATTRIBUTES = 0x100
FILE_SHARE_READ, FILE_SHARE_DELETE = 0x1, 0x4
CREATE_NEW, OPEN_EXISTING = 1, 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
INVALID_HANDLE = wintypes.HANDLE(-1).value
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_TAG_INFO = 9
FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX = 4, 21
FILE_DISPOSITION_DELETE, FILE_DISPOSITION_POSIX, FILE_DISPOSITION_IMAGE_CHECK = 0x1, 0x2, 0x4
FILE_DISPOSITION_IGNORE_READONLY = 0x10
FILE_STANDARD_INFO_CLASS = 1
FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL = 0x120116, 0x80, 0x7
FILE_CREATE, FILE_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_NON_DIRECTORY_FILE = 2, 0x1, 0x20, 0x40
FILE_OPEN_REPARSE_POINT, SYNCHRONIZE = 0x00200000, 0x00100000
STATUS_OBJECT_NAME_COLLISION = 0xC0000035
OBJ_CASE_INSENSITIVE = 0x40
SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION = 1, 0x1
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
SYSTEM_OWNERS = frozenset((TRUSTED_INSTALLER, "S-1-5-18", "S-1-5-32-544"))
# Under the Windows folder but writable by any user, so nothing there can be
# assumed to be the system's: droppers use them for exactly that reason.
USER_WRITABLE = ("Temp", "Tasks", "Tracing", "debug\\WIA", "Registration\\CRMLog",
                 "System32\\Tasks", "System32\\com\\dmp", "System32\\FxsTmp", "System32\\spool\\PRINTERS",
                 "System32\\spool\\SERVERS", "System32\\spool\\drivers\\color",
                 "SysWOW64\\Tasks", "SysWOW64\\com\\dmp", "SysWOW64\\FxsTmp")
# Set on junctions and symlinks. Cloud placeholders are reparse points too, but
# they name no other location, so they stay acceptable targets.
NAME_SURROGATE = 0x20000000
ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_ACCESS_DENIED = 2, 3, 5
ERROR_SHARING_VIOLATION, ERROR_HANDLE_EOF, ERROR_FILE_EXISTS = 32, 38, 80
ERROR_INVALID_PARAMETER, ERROR_ALREADY_EXISTS, ERROR_NOT_SUPPORTED = 87, 183, 50

class FILE_STANDARD_INFO(ctypes.Structure):
    _fields_ = [("AllocationSize", ctypes.c_int64), ("EndOfFile", ctypes.c_int64), ("NumberOfLinks", wintypes.DWORD),
                ("DeletePending", ctypes.c_ubyte), ("Directory", ctypes.c_ubyte)]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", wintypes.LPWSTR)]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
                ("ObjectName", ctypes.POINTER(UNICODE_STRING)), ("Attributes", wintypes.ULONG),
                ("SecurityDescriptor", ctypes.c_void_p), ("SecurityQualityOfService", ctypes.c_void_p)]


class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]


if os.name == "nt":
    import msvcrt

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _nt = ctypes.WinDLL("ntdll")
    _nt.NtCreateFile.restype = ctypes.c_long
    _nt.NtCreateFile.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, ctypes.POINTER(OBJECT_ATTRIBUTES),
                                 ctypes.POINTER(IO_STATUS_BLOCK), ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG,
                                 wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG]
    _k32.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_char_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                               ctypes.c_void_p]
    _k32.LocalFree.argtypes = [ctypes.c_void_p]
    _k32.ReOpenFile.restype = wintypes.HANDLE
    _k32.ReOpenFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
    _adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                                     ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.POINTER(ctypes.c_void_p)]
    _adv.GetSecurityInfo.restype = wintypes.DWORD
    _adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _k32.SetFileInformationByHandle.restype = wintypes.BOOL
    _k32.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _k32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    _k32.FindFirstFileNameW.restype = wintypes.HANDLE
    _k32.FindFirstFileNameW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR]
    _k32.FindNextFileNameW.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR]
    _k32.FindNextFileNameW.restype = wintypes.BOOL
    _k32.FindClose.argtypes = [wintypes.HANDLE]
    _k32.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    _k32.GetWindowsDirectoryW.restype = wintypes.UINT


class TargetError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


def _fail(path: str) -> TargetError:
    code = ctypes.get_last_error()
    if code in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
        return TargetError("MISSING", path)
    if code == ERROR_ACCESS_DENIED:
        return TargetError("ACCESS_DENIED", path)
    if code == ERROR_SHARING_VIOLATION:
        return TargetError("IN_USE", path)
    return TargetError("FAILED", f"{path} (Windows error {code})")


def same_path(a: str, b: str) -> bool:
    return ntpath.normcase(ntpath.normpath(a)) == ntpath.normcase(ntpath.normpath(b))


class Target:
    """One open name of a file. Closing it is what carries out a marked deletion."""

    def __init__(self, stream: BinaryIO, path: str) -> None:
        self.stream = stream
        self.path = path
        self.handle = msvcrt.get_osfhandle(stream.fileno())
        self.posix = True  # the extended delete worked, or nothing was deleted yet

    @property
    def key(self) -> tuple[int, str]:
        info = os.fstat(self.stream.fileno())
        return info.st_dev, f"{info.st_ino:032x}"

    @property
    def size(self) -> int:
        return os.fstat(self.stream.fileno()).st_size

    def generation(self) -> tuple[int, str, int, int, int]:
        info = os.fstat(self.stream.fileno())
        return (info.st_dev, f"{info.st_ino:032x}", info.st_size, info.st_mtime_ns,
                identity._change_time(self.stream.fileno(), info))

    def other_names(self) -> list[str]:
        if os.fstat(self.stream.fileno()).st_nlink < 2:
            return []
        return [name for name in _link_names(self.path) if not same_path(name, self.path)]

    def mark_delete(self, delete: bool = True) -> None:
        # The read-only attribute must not be a way to stay out of quarantine.
        # POSIX: the name goes when this handle closes, whoever else holds the
        # file. The image check keeps a running program a refusal: its process
        # would otherwise go on running from a file nobody can see any more.
        # File systems without the extended call fall back to the classic one.
        flags = (FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX | FILE_DISPOSITION_IMAGE_CHECK
                 | FILE_DISPOSITION_IGNORE_READONLY) if delete else 0
        ex = wintypes.DWORD(flags)
        if _k32.SetFileInformationByHandle(self.handle, FILE_DISPOSITION_INFO_EX, ctypes.byref(ex), 4):
            return
        if ctypes.get_last_error() not in (ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED):
            raise _fail(self.path)
        plain = ctypes.c_ubyte(1 if delete else 0)
        if not _k32.SetFileInformationByHandle(self.handle, FILE_DISPOSITION_INFO, ctypes.byref(plain), 1):
            raise _fail(self.path)
        self.posix = False

    def watch(self) -> Target:
        """A handle that only looks, on this very file with no name involved.

        It outlives the deletion and can tell whether any name did. Opening the
        name again would look at whatever was swapped in there meanwhile.
        """
        handle = _k32.ReOpenFile(self.handle, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, FILE_FLAG_OPEN_REPARSE_POINT)
        if handle in (None, INVALID_HANDLE):
            raise _fail(self.path)
        return Target(os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY), "rb", buffering=0), self.path)

    def _standard_info(self) -> FILE_STANDARD_INFO:
        info = FILE_STANDARD_INFO()
        if not _k32.GetFileInformationByHandleEx(self.handle, FILE_STANDARD_INFO_CLASS, ctypes.byref(info),
                                                 ctypes.sizeof(info)):
            raise _fail(self.path)
        return info

    def gone(self) -> bool:
        """Someone already deleted this file; this handle only keeps the bytes alive."""
        info = self._standard_info()
        return bool(info.DeletePending) or info.NumberOfLinks == 0

    def survives(self, *, posix: bool) -> bool:
        """After every name was deleted: is any still there?

        Measured on NTFS: the link count leaves out deleted names, while the
        pending flag stays set once this name went, even if another one lives.
        The classic delete on file systems without links has only the flag.
        """
        info = self._standard_info()
        return info.NumberOfLinks > 0 if posix else not info.DeletePending

    def owner(self) -> str | None:
        owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
        if _adv.GetSecurityInfo(self.handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, ctypes.byref(owner),
                                None, None, None, ctypes.byref(descriptor)):
            return None
        try:
            text = wintypes.LPWSTR()
            if not _adv.ConvertSidToStringSidW(owner, ctypes.byref(text)):
                return None
            try:
                return text.value
            finally:
                _k32.LocalFree(text)
        finally:
            _k32.LocalFree(descriptor)

    def system_owned(self) -> bool:
        # Not knowing counts as the system's: the mistake to avoid is breaking Windows.
        found = self.owner()
        return found is None or found in SYSTEM_OWNERS

    def write_stream(self, name: str, data: bytes) -> None:
        """Writes a stream of the file this handle holds; a path would be looked up again."""
        length = len(name) * 2
        text = UNICODE_STRING(length, length, name)
        attributes = OBJECT_ATTRIBUTES(ctypes.sizeof(OBJECT_ATTRIBUTES), self.handle, ctypes.pointer(text),
                                       OBJ_CASE_INSENSITIVE, None, None)
        status_block = IO_STATUS_BLOCK()
        opened = wintypes.HANDLE()
        status = _nt.NtCreateFile(ctypes.byref(opened), FILE_GENERIC_WRITE, ctypes.byref(attributes),
                                  ctypes.byref(status_block), None, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_ALL, FILE_CREATE,
                                  FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, None, 0)
        if status:
            raise TargetError("FAILED", f"stream status {status & 0xFFFFFFFF:#x}")
        try:
            done = wintypes.DWORD()
            if not _k32.WriteFile(opened, data, len(data), ctypes.byref(done), None) or done.value != len(data):
                raise _fail(name)
        finally:
            _k32.CloseHandle(opened)

    def close(self) -> None:
        self.stream.close()


def _reparse_tag(handle: int, path: str) -> int:
    info = (ctypes.c_uint32 * 2)()
    if not _k32.GetFileInformationByHandleEx(handle, FILE_ATTRIBUTE_TAG_INFO, info, ctypes.sizeof(info)):
        raise _fail(path)
    attributes, tag = struct.unpack("<II", bytes(info))
    return tag if attributes & FILE_ATTRIBUTE_REPARSE_POINT else 0


def _open(path: str, access: int, share: int, disposition: int, attributes: int, mode: int, how: str) -> Target:
    if os.name != "nt":
        raise TargetError("WINDOWS_REQUIRED", path)
    handle = _k32.CreateFileW(path, access, share, None, disposition,
                              attributes | FILE_FLAG_OPEN_REPARSE_POINT, None)
    if handle in (None, INVALID_HANDLE):
        code = ctypes.get_last_error()
        if code in (ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS):
            raise FileExistsError(path)
        ctypes.set_last_error(code)
        raise _fail(path)
    try:
        stream = os.fdopen(msvcrt.open_osfhandle(handle, mode), how, buffering=0)
    except OSError:
        _k32.CloseHandle(handle)
        raise
    target = Target(stream, path)
    try:
        target.path = identity._final_path(stream.fileno(), path)
    except OSError as e:
        stream.close()
        raise TargetError("FAILED", path) from e
    return target


def open_target(path: str) -> Target:
    """Opens a name of a regular file, keeping writers out while it is held.

    FILE_SHARE_DELETE stays on because sharing belongs to the file, not to the
    name: without it a second hard link could not be opened for deletion.
    """
    target = _open(path, GENERIC_READ | DELETE | FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_DELETE,
                   OPEN_EXISTING, 0, os.O_RDONLY | os.O_BINARY, "rb")
    try:
        if _reparse_tag(target.handle, path) & NAME_SURROGATE:
            raise TargetError("REPARSE_POINT", path)
        if not stat.S_ISREG(os.fstat(target.stream.fileno()).st_mode):
            raise TargetError("NOT_REGULAR", path)
    except BaseException:
        target.close()
        raise
    return target


def create_new(path: str) -> Target:
    """Creates a file and proves where it landed before any content is written.

    A parent folder swapped for a junction would redirect a privileged write
    into a location the user could never write to. Nothing else can open the
    file while it is held, so an empty file in the wrong place harms nobody and
    is removed through its handle.
    """
    target = _open(path, GENERIC_WRITE | DELETE, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                   os.O_WRONLY | os.O_BINARY, "wb")
    if not same_path(target.path, path):
        try:
            target.mark_delete()
        finally:
            target.close()
        raise TargetError("MOVED", path)
    return target


def _new_directory(path: str) -> int | None:
    """A handle to the folder this call created; None if the name was taken."""
    name = "\\??\\" + path
    length = len(name.encode("utf-16-le", "surrogatepass"))
    text = UNICODE_STRING(length, length, name)
    attributes = OBJECT_ATTRIBUTES(ctypes.sizeof(OBJECT_ATTRIBUTES), None, ctypes.pointer(text),
                                   OBJ_CASE_INSENSITIVE, None, None)
    status_block = IO_STATUS_BLOCK()
    opened = wintypes.HANDLE()
    status = _nt.NtCreateFile(ctypes.byref(opened), DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                              ctypes.byref(attributes), ctypes.byref(status_block), None, FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_ALL, FILE_CREATE,
                              FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, None, 0)
    if status & 0xFFFFFFFF == STATUS_OBJECT_NAME_COLLISION:
        return None
    if status:
        raise TargetError("FAILED", f"{path}: status {status & 0xFFFFFFFF:#x}")
    return int(opened.value)


def make_parents(path: str) -> None:
    """Creates missing folders one by one, proving each landed where it was named.

    The handle comes from the creation itself. Opening the name again afterwards
    could reach any folder a junction was flipped to, and removing that would
    hand LocalSystem's delete to whoever flipped it.
    """
    missing: list[str] = []
    folder = ntpath.dirname(path)
    while folder and not os.path.lexists(folder):
        missing.append(folder)
        parent = ntpath.dirname(folder)
        if parent == folder:
            break
        folder = parent
    for item in reversed(missing):
        handle = _new_directory(item)
        if handle is None:
            continue  # someone else made it meanwhile, and create_new checks where it leads
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY)
        try:
            if not same_path(identity._final_path(descriptor, item), item):
                remove = ctypes.c_ubyte(1)
                _k32.SetFileInformationByHandle(handle, FILE_DISPOSITION_INFO, ctypes.byref(remove), 1)
                raise TargetError("MOVED", item)
        finally:
            os.close(descriptor)


def _link_names(final: str) -> list[str]:
    drive = ntpath.splitdrive(final)[0]
    name = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(name))
    finder = _k32.FindFirstFileNameW(final, 0, ctypes.byref(size), name)
    if finder in (None, INVALID_HANDLE):
        raise _fail(final)
    try:
        names = [drive + name.value]
        while True:
            size.value = len(name)
            if not _k32.FindNextFileNameW(finder, ctypes.byref(size), name):
                if ctypes.get_last_error() != ERROR_HANDLE_EOF:
                    raise _fail(final)
                return names
            names.append(drive + name.value)
    finally:
        _k32.FindClose(finder)


def _windows_dir() -> str:
    buffer = ctypes.create_unicode_buffer(32768)
    if not _k32.GetWindowsDirectoryW(buffer, len(buffer)):
        raise _fail("GetWindowsDirectory")
    return buffer.value


def protected_roots() -> tuple[str, ...]:
    """Folders no action may touch: a false positive there breaks the machine."""
    roots = [_windows_dir()]
    program_files, program_data = os.environ.get("ProgramFiles"), os.environ.get("ProgramData")
    if program_files:
        roots += [ntpath.join(program_files, "Windows Defender"), ntpath.join(program_files, "SentinelGuard")]
    if program_data:
        roots.append(ntpath.join(program_data, "Microsoft", "Windows Defender"))
    return tuple(ntpath.normcase(ntpath.normpath(root)) for root in roots)


def is_protected(path: str, roots: tuple[str, ...] | None = None) -> bool:
    found = ntpath.normcase(ntpath.normpath(path))
    windows = _windows_dir()
    if any(found.startswith(ntpath.normcase(ntpath.join(windows, folder)) + "\\") for folder in USER_WRITABLE):
        return False
    return any(found == root or found.startswith(root + "\\") for root in (roots or protected_roots()))
