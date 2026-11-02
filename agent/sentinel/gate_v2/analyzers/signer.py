"""PE certificate declaration and separate Windows trust context."""

from __future__ import annotations

import ctypes
import os
import threading
import time
from collections.abc import Callable
from ctypes import wintypes
from typing import Literal

from .. import identity
from ..content import BoundReader, ContentError
from ..contract import (ByteRange, CancellationToken, Category, EngineResult,
                        FileIdentity, ScanRequest, StageStatus, Strength)
from . import context_evidence, result

TrustState = Literal["valid", "unsigned", "invalid", "revoked", "unavailable"]
TrustCheck = Callable[[str], TrustState]
MAX_HEADER = 4096
_TRUST_SLOT = threading.BoundedSemaphore(1)


def certificate_present(data: bytes, file_size: int) -> tuple[bool | None, str]:
    if not data.startswith(b"MZ"):
        return None, "not_pe"
    try:
        if len(data) < 64:
            return None, "malformed"
        pe = int.from_bytes(data[0x3c:0x40], "little")
        if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
            return None, "malformed"
        opt_size = int.from_bytes(data[pe + 20:pe + 22], "little")
        opt = pe + 24
        if opt + opt_size > len(data):
            return None, "partial"
        magic = int.from_bytes(data[opt:opt + 2], "little")
        if magic not in (0x10b, 0x20b):
            return None, "malformed"
        directory = opt + (96 if magic == 0x10b else 112)
        if directory + 40 > opt + opt_size:
            return None, "partial"
        entry = directory + 32
        offset = int.from_bytes(data[entry:entry + 4], "little")
        size = int.from_bytes(data[entry + 4:entry + 8], "little")
        if not offset and not size:
            return False, "complete"
        if not offset or size < 8 or offset + size > file_size:
            return None, "malformed"
        return True, "complete"
    except (ValueError, OverflowError):
        return None, "malformed"


def win_verify_trust(path: str) -> TrustState:
    if os.name != "nt":
        return "unavailable"
    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]
    class FileInfo(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]
    class WinTrustData(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(FileInfo)), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]
    action = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                  (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    info = FileInfo(ctypes.sizeof(FileInfo), path, None, None)
    # Cache-only retrieval prevents an implicit network revocation request.
    data = WinTrustData(ctypes.sizeof(WinTrustData), None, None, 2, 0, 1,
                        ctypes.pointer(info), 0, None, None, 0x1000, 0, None)
    try:
        api = ctypes.WinDLL("wintrust", use_last_error=True).WinVerifyTrust
        api.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WinTrustData)]
        api.restype = ctypes.c_long
        code = api(None, ctypes.byref(action), ctypes.byref(data)) & 0xffffffff
    except (OSError, AttributeError, ValueError):
        return "unavailable"
    if code == 0:
        return "valid"
    if code in (0x800B010C, 0x80092010):
        return "revoked"
    if code == 0x800B0100:
        return "unsigned"
    return "invalid"


class SignerAdapter:
    engine_id = "signer"
    reopens_path = False

    def __init__(self, trust: TrustCheck = win_verify_trust) -> None:
        self.trust = trust

    def readiness(self) -> str:
        return "READY"

    def _bounded_trust(self, path: str, deadline_ns: int,
                       cancel: CancellationToken) -> TrustState:
        remaining = max(0.0, (deadline_ns - time.monotonic_ns()) / 1e9)
        if not _TRUST_SLOT.acquire(timeout=remaining):
            return "unavailable"
        finished = threading.Event()
        value: list[TrustState] = ["unavailable"]
        def run() -> None:
            try:
                value[0] = self.trust(path)
            except Exception:
                pass
            finally:
                _TRUST_SLOT.release()
                finished.set()
        threading.Thread(target=run, daemon=True).start()
        while not finished.is_set():
            if cancel.cancelled() or time.monotonic_ns() >= deadline_ns:
                return "unavailable"
            finished.wait(max(0.0, min(0.1, (deadline_ns - time.monotonic_ns()) / 1e9)))
        return value[0]

    def scan_bound(self, request: ScanRequest, measured: FileIdentity,
                   cancel: CancellationToken, reader: BoundReader) -> EngineResult:
        start = time.monotonic_ns()
        try:
            header = reader.read(0, min(measured.size, MAX_HEADER), cancel)
            span = reader.ranges
            present, state = certificate_present(header, measured.size)
            if state == "not_pe":
                return result(self.engine_id, request, measured, start, StageStatus.COMPLETED,
                              "NOT_PE", span)
            if state != "complete":
                return result(self.engine_id, request, measured, start, StageStatus.PARTIAL,
                              "PE_HEADER_" + state.upper(), span, parser_state=state)
            evidence = [context_evidence(self.engine_id,
                        "CERTIFICATE_PRESENT" if present else "CERTIFICATE_ABSENT",
                        Category.STRUCTURE, Strength.CONTEXT, span)]
            trust_state: TrustState = "unavailable"
            if request.path and present:
                if not identity.revalidate(request.path, measured, rehash=True).ok:
                    return result(self.engine_id, request, measured, start, StageStatus.CHANGED,
                                  "CHANGED", span, parser_state="changed")
                trust_state = self._bounded_trust(request.path, request.deadline_monotonic_ns, cancel)
                if cancel.cancelled():
                    return result(self.engine_id, request, measured, start, StageStatus.CANCELLED,
                                  "CANCELLED", span, parser_state="cancelled")
                if time.monotonic_ns() >= request.deadline_monotonic_ns:
                    return result(self.engine_id, request, measured, start, StageStatus.TIMEOUT,
                                  "DEADLINE", span, parser_state="timeout")
                if not identity.revalidate(request.path, measured, rehash=True).ok:
                    return result(self.engine_id, request, measured, start, StageStatus.CHANGED,
                                  "CHANGED", span, parser_state="changed")
            if trust_state not in ("valid", "unsigned", "invalid", "revoked", "unavailable"):
                trust_state = "unavailable"
            evidence.append(context_evidence(self.engine_id, "TRUST_" + trust_state.upper(),
                                             Category.STRUCTURE, Strength.CONTEXT, span))
            return result(self.engine_id, request, measured, start, StageStatus.COMPLETED,
                          "READY", span, tuple(evidence))
        except ContentError as exc:
            status = StageStatus.CHANGED if exc.code == "CHANGED" else StageStatus.CANCELLED if exc.code == "CANCELLED" else StageStatus.ERROR
            return result(self.engine_id, request, measured, start, status, exc.code,
                          reader.ranges, parser_state="error")
        except Exception:
            return result(self.engine_id, request, measured, start, StageStatus.ERROR,
                          "SIGNER_ERROR", reader.ranges, parser_state="error")
