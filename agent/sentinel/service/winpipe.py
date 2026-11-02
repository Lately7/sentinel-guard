"""Windows named-pipe transport for ServiceCore (R13 §1, R13b P3).

Stdlib + ctypes only. The caller identity handed to ServiceCore comes from the
connected client's token (impersonate, query, revert), never from the request.
Works unelevated for same-user tests; the service DACL and LocalSystem checks
belong to the owner's elevated acceptance script.
"""

from __future__ import annotations

import ctypes
import logging
import os
import secrets
import threading
from ctypes import wintypes
from dataclasses import replace
from typing import Any

from .authz import Caller
from .core import ServiceCore
from .protocol import ProtocolError, error, read_frame, write_frame

log = logging.getLogger(__name__)

PIPE_NAME = r"\\.\pipe\SentinelGuard\v1"
# SYSTEM and Administrators: full control. Interactive users: read/write data
# only — not FILE_CREATE_PIPE_INSTANCE (0x4, part of generic write), so a user
# process cannot add its own instance of our pipe and receive our clients.
SERVICE_SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012008B;;;IU)"
# Exactly that grant: GENERIC_WRITE would also ask for the right to add an
# instance, which is refused, and no client could connect at all.
CLIENT_ACCESS = 0x0012008B
MAX_CONNECTIONS = 32
BUFFER = 64 * 1024
SE_FILE_OBJECT, SE_KERNEL_OBJECT = 1, 6
OWNER_SECURITY_INFORMATION = 0x1
FILE_OBJECT_SECURITY = 0x7  # owner, group and DACL: what AccessCheck needs
FILE_READ_DATA, FILE_READ_ATTRIBUTES, READ_CONTROL = 0x1, 0x80, 0x00020000
FILE_SHARE_ALL = 0x7
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS = 0x120089, 0x120116, 0x1200A0, 0x1F01FF

if os.name == "nt":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)

    PIPE_ACCESS_DUPLEX = 0x3
    FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
    PIPE_TYPE_BYTE, PIPE_READMODE_BYTE, PIPE_WAIT = 0x0, 0x0, 0x0
    PIPE_REJECT_REMOTE_CLIENTS = 0x8
    PIPE_UNLIMITED_INSTANCES = 255
    OPEN_EXISTING = 3
    SECURITY_SQOS_PRESENT = 0x00100000
    SECURITY_IDENTIFICATION = 0x00010000
    ERROR_PIPE_CONNECTED = 535
    ERROR_BROKEN_PIPE = 109
    ERROR_NO_DATA = 232
    ERROR_PIPE_NOT_CONNECTED = 233  # the other side disconnected: end of stream
    TOKEN_QUERY, TOKEN_DUPLICATE = 0x8, 0x2
    TokenUser, TokenElevation, TokenIntegrityLevel, TokenSessionId = 1, 20, 25, 12
    INVALID_HANDLE = wintypes.HANDLE(-1).value

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    _k32.CreateNamedPipeW.restype = wintypes.HANDLE
    _k32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    _k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    _k32.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                               ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    _k32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.GetCurrentThread.restype = wintypes.HANDLE
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.LocalFree.argtypes = [ctypes.c_void_p]
    _k32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                                     ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.POINTER(ctypes.c_void_p)]
    _adv.GetSecurityInfo.restype = wintypes.DWORD
    _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    _adv.ImpersonateNamedPipeClient.argtypes = [wintypes.HANDLE]
    _adv.RevertToSelf.argtypes = []
    _adv.OpenThreadToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, ctypes.POINTER(wintypes.HANDLE)]
    _adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD)]
    _adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _adv.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    _adv.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    _adv.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    _adv.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    _adv.CreateWellKnownSid.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    _adv.DuplicateToken.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
    _adv.CheckTokenMembership.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL)]
    _adv.AccessCheck.argtypes = [ctypes.c_void_p, wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                                 ctypes.POINTER(wintypes.BOOL)]


class PipeError(OSError):
    pass


def _fail(what: str) -> PipeError:
    code = ctypes.get_last_error()
    return PipeError(code, f"{what} failed (Windows error {code})")


class PipeStream:
    """Minimal binary stream over a pipe handle, enough for read_frame/write_frame."""

    def __init__(self, handle: int) -> None:
        self.handle = handle

    def read(self, n: int) -> bytes:
        buf = ctypes.create_string_buffer(min(max(n, 1), BUFFER))
        got = wintypes.DWORD(0)
        if not _k32.ReadFile(self.handle, buf, len(buf), ctypes.byref(got), None):
            if ctypes.get_last_error() in (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED):
                return b""
            raise _fail("ReadFile")
        return buf.raw[:got.value]

    def write(self, data: bytes) -> int:
        view = memoryview(data)
        while view:
            done = wintypes.DWORD(0)
            if not _k32.WriteFile(self.handle, ctypes.c_char_p(bytes(view[:BUFFER])), min(len(view), BUFFER),
                                  ctypes.byref(done), None):
                raise _fail("WriteFile")
            view = view[done.value:]
        return len(data)

    def flush(self) -> None:
        _k32.FlushFileBuffers(self.handle)

    def close(self) -> None:
        if self.handle:
            _k32.CloseHandle(self.handle)
            self.handle = 0


# -- token inspection


def _token_info(token: int, cls: int) -> ctypes.Array[Any]:
    need = wintypes.DWORD(0)
    _adv.GetTokenInformation(token, cls, None, 0, ctypes.byref(need))
    buf = ctypes.create_string_buffer(max(need.value, 4))
    if not _adv.GetTokenInformation(token, cls, buf, len(buf), ctypes.byref(need)):
        raise _fail("GetTokenInformation")
    return buf


def _sid_string(psid: int) -> str:
    out = wintypes.LPWSTR()
    if not _adv.ConvertSidToStringSidW(psid, ctypes.byref(out)):
        raise _fail("ConvertSidToStringSid")
    try:
        return out.value or ""
    finally:
        _k32.LocalFree(out)


_RID_TO_LEVEL = ((0x4000, "system"), (0x3000, "high"), (0x2000, "medium"), (0x1000, "low"), (0, "untrusted"))


def caller_from_token(token: int, *, remote: bool = False) -> Caller:
    user = _token_info(token, TokenUser)
    sid = _sid_string(ctypes.cast(user, ctypes.POINTER(ctypes.c_void_p))[0])
    label = _token_info(token, TokenIntegrityLevel)
    psid = ctypes.cast(label, ctypes.POINTER(ctypes.c_void_p))[0]
    count = _adv.GetSidSubAuthorityCount(psid)[0]
    rid = _adv.GetSidSubAuthority(psid, count - 1)[0]
    integrity = next(name for floor, name in _RID_TO_LEVEL if rid >= floor)
    elevated = bool(ctypes.cast(_token_info(token, TokenElevation), ctypes.POINTER(wintypes.DWORD))[0])
    session = ctypes.cast(_token_info(token, TokenSessionId), ctypes.POINTER(wintypes.DWORD))[0]
    # Membership is checked on the token itself, so a filtered (UAC split)
    # token of an administrator does not count as admin.
    admins = ctypes.create_string_buffer(68)
    size = wintypes.DWORD(len(admins))
    if not _adv.CreateWellKnownSid(26, None, admins, ctypes.byref(size)):  # WinBuiltinAdministratorsSid
        raise _fail("CreateWellKnownSid")
    member = wintypes.BOOL(False)
    if not _adv.CheckTokenMembership(token, admins, ctypes.byref(member)):
        member = wintypes.BOOL(False)
    return Caller(sid, int(session), integrity, bool(member.value) and elevated, remote)


def current_process_caller() -> Caller:
    token = wintypes.HANDLE()
    if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), TOKEN_QUERY | 0x2, ctypes.byref(token)):  # + DUPLICATE
        raise _fail("OpenProcessToken")
    try:
        # CheckTokenMembership needs an impersonation token, so the facts are
        # read from an identification-level duplicate of the process token.
        dup = wintypes.HANDLE()
        if not _adv.DuplicateToken(token, 1, ctypes.byref(dup)):  # SecurityIdentification
            raise _fail("DuplicateToken")
        try:
            return caller_from_token(dup.value)
        finally:
            _k32.CloseHandle(dup)
    finally:
        _k32.CloseHandle(token)


def server_pipe_owner(stream: PipeStream) -> str:
    """SID that owns this connected pipe instance.

    A medium-integrity client cannot open a LocalSystem process or its token, so
    asking who the server process is would fail against the real service. The
    owner is readable from our own handle, and a same-user process squatting the
    name can only make itself the owner.
    """
    if os.name != "nt":
        raise PipeError(0, "named pipes need Windows")
    owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    code = _adv.GetSecurityInfo(stream.handle, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
                                ctypes.byref(owner), None, None, None, ctypes.byref(descriptor))
    if code:
        raise PipeError(code, f"GetSecurityInfo(pipe) failed (Windows error {code})")
    try:
        return _sid_string(owner.value)
    finally:
        _k32.LocalFree(descriptor)


def duplicate_token(token: int) -> int:
    """A token of our own, for work that outlives the connection it came from."""
    dup = wintypes.HANDLE()
    if not _adv.DuplicateToken(token, 1, ctypes.byref(dup)):  # SecurityIdentification
        raise _fail("DuplicateToken")
    return int(dup.value)


def close_token(token: int) -> None:
    _k32.CloseHandle(token)


class GENERIC_MAPPING(ctypes.Structure):
    _fields_ = [("read", wintypes.DWORD), ("write", wintypes.DWORD),
                ("execute", wintypes.DWORD), ("all", wintypes.DWORD)]


def client_can_read(token: int | None, path: str) -> bool:
    """Whether the file's own DACL lets this client read it.

    AccessCheck rather than impersonation: clients connect at identification
    level, so that a squatter on the pipe name can never act as them, and at
    that level the service can ask about a token but not open files with it.
    """
    if os.name != "nt" or token is None:
        return False
    handle = _k32.CreateFileW(path, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, None, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, None)
    if handle in (None, INVALID_HANDLE):
        return False
    descriptor = ctypes.c_void_p()
    try:
        if _adv.GetSecurityInfo(handle, SE_FILE_OBJECT, FILE_OBJECT_SECURITY, None, None, None, None,
                                ctypes.byref(descriptor)):
            return False
        mapping = GENERIC_MAPPING(FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS)
        privileges = ctypes.create_string_buffer(256)
        size, granted, allowed = wintypes.DWORD(len(privileges)), wintypes.DWORD(0), wintypes.BOOL(False)
        if not _adv.AccessCheck(descriptor, token, FILE_READ_DATA, ctypes.byref(mapping), privileges,
                                ctypes.byref(size), ctypes.byref(granted), ctypes.byref(allowed)):
            return False
        return bool(allowed.value)
    finally:
        if descriptor:
            _k32.LocalFree(descriptor)
        _k32.CloseHandle(handle)


def file_owner(path: str) -> str | None:
    """Whose file this is, for work no client asked for: they should see what happened to it."""
    if os.name != "nt":
        return None
    handle = _k32.CreateFileW(path, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, None, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, None)
    if handle in (None, INVALID_HANDLE):
        return None
    owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    try:
        if _adv.GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, ctypes.byref(owner), None,
                                None, None, ctypes.byref(descriptor)):
            return None
        return _sid_string(owner.value)
    except PipeError:
        return None
    finally:
        if descriptor:
            _k32.LocalFree(descriptor)
        _k32.CloseHandle(handle)


def _identify_client(handle: int) -> Caller:
    if not _adv.ImpersonateNamedPipeClient(handle):
        raise _fail("ImpersonateNamedPipeClient")
    try:
        token = wintypes.HANDLE()
        if not _adv.OpenThreadToken(_k32.GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, True, ctypes.byref(token)):
            raise _fail("OpenThreadToken")
        try:
            return replace(caller_from_token(token.value), token=int(token.value))
        except BaseException:
            _k32.CloseHandle(token)
            raise
    finally:
        # Never keep running as the client, whatever happened above.
        if not _adv.RevertToSelf():
            os._exit(70)  # cannot drop the client's identity: stop rather than act as them


# -- server


class PipeServer:
    def __init__(self, core: ServiceCore, *, name: str = PIPE_NAME, sddl: str = SERVICE_SDDL,
                 max_connections: int = MAX_CONNECTIONS) -> None:
        if os.name != "nt":
            raise PipeError(0, "named pipes need Windows")
        self.core, self.name, self.sddl = core, name, sddl
        self._slots = threading.BoundedSemaphore(max_connections)
        self._stop = threading.Event()
        self._first = True
        self._sd = ctypes.c_void_p()
        if not _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(self._sd), None):
            raise _fail("ConvertStringSecurityDescriptorToSecurityDescriptor")
        # Created now, so a name already taken by someone else fails start-up
        # instead of letting us serve next to (or behind) a squatter.
        self._pending = self._new_instance()

    def _new_instance(self) -> int:
        sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), self._sd, False)
        flags = PIPE_ACCESS_DUPLEX | (FILE_FLAG_FIRST_PIPE_INSTANCE if self._first else 0)
        handle = _k32.CreateNamedPipeW(self.name, flags,
                                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                       PIPE_UNLIMITED_INSTANCES, BUFFER, BUFFER, 0, ctypes.byref(sa))
        if handle in (None, INVALID_HANDLE):
            raise _fail("CreateNamedPipe")
        self._first = False
        return handle

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            handle = self._pending
            ok = _k32.ConnectNamedPipe(handle, None) or ctypes.get_last_error() == ERROR_PIPE_CONNECTED
            if self._stop.is_set():
                _k32.CloseHandle(handle)
                return
            try:
                self._pending = self._new_instance()
            except PipeError:
                log.exception("cannot create the next pipe instance")
                self._stop.set()
            if not ok or not self._slots.acquire(blocking=False):
                _k32.DisconnectNamedPipe(handle)
                _k32.CloseHandle(handle)
                continue
            threading.Thread(target=self._client, args=(handle,), daemon=True, name="pipe-client").start()

    def _client(self, handle: int) -> None:
        stream = PipeStream(handle)
        connection_id = secrets.token_hex(16)
        caller: Caller | None = None
        try:
            while not self._stop.is_set():
                try:
                    frame = read_frame(stream)
                except ProtocolError as e:
                    write_frame(stream, error(None, e.code, str(e)))
                    return
                if frame is None:
                    return
                if caller is None:
                    # Impersonation needs data from the client first; the
                    # identity is then fixed for the whole connection.
                    try:
                        caller = _identify_client(handle)
                    except PipeError:
                        write_frame(stream, error(None, "FORBIDDEN", "caller could not be identified"))
                        return
                write_frame(stream, self.core.handle(caller, frame, connection_id=connection_id))
        except PipeError:
            return
        finally:
            if caller is not None and caller.token is not None:
                close_token(caller.token)
            _k32.DisconnectNamedPipe(handle)
            stream.close()
            self._slots.release()

    def stop(self) -> None:
        self._stop.set()
        self.core.stop()
        # Unblock ConnectNamedPipe with a throw-away connection.
        try:
            connect(self.name).close()
        except PipeError:
            pass


def connect(name: str = PIPE_NAME) -> PipeStream:
    """Client side. Identification level only: a server that is not ours (a
    squatter on the name) learns who we are but cannot act as us."""
    if os.name != "nt":
        raise PipeError(0, "named pipes need Windows")
    handle = _k32.CreateFileW(name, CLIENT_ACCESS, 0, None, OPEN_EXISTING,
                              SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, None)
    if handle in (None, INVALID_HANDLE):
        raise _fail("CreateFile(pipe)")
    return PipeStream(handle)
