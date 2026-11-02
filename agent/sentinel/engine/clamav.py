"""ClamAV layer: a private clamd instance queried over its INSTREAM protocol.

ClamAV is the open-source engine with the largest public signature set, and it
unpacks containers this agent does not (7z, RAR, CAB, ISO, MSI, PDF streams,
OLE2, packed PE). Each scan of a file costs a full signature-database load
when done with clamscan, so a long-running clamd is used instead and files are
streamed to it: clamd never needs read access to the user's paths, and the
bytes it judges are exactly the bytes this agent hashed.

The daemon, its configuration and its database live under the agent's data
directory, so nothing in Program Files has to be writable.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

from .. import config
from .verdict import Finding, Severity

log = logging.getLogger(__name__)

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
HOST = "127.0.0.1"
DEFAULT_PORT = 33310
CHUNK = 256 * 1024
# clamd silently answers "OK" for a file above MaxFileSize (AlertExceedsMax
# would flag every big installer instead), so files above this limit are never
# sent and are reported as not checked by ClamAV rather than as clean.
MAX_FILE_MB = 400
STREAM_MAX_BYTES = MAX_FILE_MB * 1024 * 1024
DATABASE_FILES = ("main.cvd", "main.cld", "daily.cvd", "daily.cld")


def install_dir() -> Path | None:
    override = os.environ.get("SENTINEL_CLAMAV_DIR")
    cands = [Path(override)] if override else []
    cands.append(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV")
    found = shutil.which("clamd")
    if found:
        cands.append(Path(found).parent)
    for c in cands:
        if (c / _exe("clamd")).is_file():
            return c
    return None


def _exe(name: str) -> str:
    return f"{name}.exe" if os.name == "nt" else name


def home() -> Path:
    p = config.data_dir() / "clamav"
    (p / "db").mkdir(parents=True, exist_ok=True)
    return p


def db_dir() -> Path:
    return home() / "db"


def port() -> int:
    raw = os.environ.get("SENTINEL_CLAMD_PORT", "")
    return int(raw) if raw.isdigit() and 1024 < int(raw) < 65536 else DEFAULT_PORT


def has_database() -> bool:
    d = db_dir()
    return any((d / n).is_file() for n in DATABASE_FILES[:2]) and any((d / n).is_file() for n in DATABASE_FILES[2:])


def write_configs() -> tuple[Path, Path]:
    h = home()
    clamd_conf = h / "clamd.conf"
    fresh_conf = h / "freshclam.conf"
    clamd_conf.write_text("\n".join([
        f"DatabaseDirectory {db_dir()}",
        f"LogFile {h / 'clamd.log'}",
        "LogFileMaxSize 5M",
        "LogRotate yes",
        "LogTime yes",
        f"TCPAddr {HOST}",
        f"TCPSocket {port()}",
        "Foreground yes",
        "MaxThreads 4",
        "ReadTimeout 120",
        "CommandReadTimeout 30",
        f"StreamMaxLength {MAX_FILE_MB + 1}M",
        f"MaxScanSize {MAX_FILE_MB * 4}M",
        f"MaxFileSize {MAX_FILE_MB + 1}M",
        "MaxRecursion 17",
        "MaxFiles 10000",
        "MaxScanTime 120000",
        "ScanPE yes", "ScanELF yes", "ScanOLE2 yes", "ScanPDF yes", "ScanSWF yes",
        "ScanHTML yes", "ScanXMLDOCS yes", "ScanHWP3 yes", "ScanArchive yes", "ScanMail yes",
        "Bytecode yes",
        "HeuristicAlerts yes",
        # The "alert on X" switches flag ordinary password-protected archives
        # and big installers; the agent reports those limits itself, softer.
        "AlertBrokenExecutables no", "AlertEncrypted no", "AlertExceedsMax no", "AlertOLE2Macros no",
        "DetectPUA no",
        "",
    ]), encoding="utf-8")
    fresh_conf.write_text("\n".join([
        f"DatabaseDirectory {db_dir()}",
        f"UpdateLogFile {h / 'freshclam.log'}",
        "LogFileMaxSize 2M",
        "LogTime yes",
        "DatabaseMirror database.clamav.net",
        "ScriptedUpdates yes",
        "Bytecode yes",
        "ConnectTimeout 30",
        "ReceiveTimeout 0",
        "",
    ]), encoding="utf-8")
    return clamd_conf, fresh_conf


def update(timeout: float = 1800.0) -> str:
    """Download/refresh the signature database with freshclam. Returns a status line."""
    d = install_dir()
    if d is None:
        return "error: ClamAV is not installed"
    _, fresh_conf = write_configs()
    argv = [str(d / _exe("freshclam")), f"--config-file={fresh_conf}", f"--datadir={db_dir()}", "--stdout"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False,
                              creationflags=NO_WINDOW, cwd=str(home()))
    except subprocess.TimeoutExpired:
        return "error: freshclam timed out"
    except OSError as e:
        return f"error: {e}"
    # freshclam returns 0 for "up to date" and "updated"; every other code is a failure
    # (freshclam/freshclam.c:2198-2203 in ClamAV 1.5.4), even when an older database exists.
    if proc.returncode != 0 or not has_database():
        tail = (proc.stdout or proc.stderr or "").strip().splitlines()[-3:]
        return f"error: freshclam exit {proc.returncode}: {' | '.join(tail)}"
    try:
        Clamd().command(b"zRELOAD\0", timeout=10)
    except OSError:
        pass  # not running: it loads the new database when it starts
    return "ok"


class ClamdError(Exception):
    pass


class Clamd:
    """Minimal client for clamd's TCP protocol (null-terminated 'z' commands)."""

    def __init__(self, host: str = HOST, port_: int | None = None) -> None:
        self.addr = (host, port_ or port())

    def command(self, cmd: bytes, timeout: float = 5.0) -> str:
        with socket.create_connection(self.addr, timeout=timeout) as s:
            s.sendall(cmd)
            return _recv_reply(s)

    def ping(self) -> bool:
        try:
            return self.command(b"zPING\0", timeout=2) == "PONG"
        except OSError:
            return False

    def version(self) -> str | None:
        try:
            return self.command(b"zVERSION\0", timeout=3)
        except OSError:
            return None

    def instream(self, data: bytes, timeout: float = 150.0) -> str:
        view = memoryview(data)
        return self._stream((view[i:i + CHUNK] for i in range(0, len(view), CHUNK)), timeout)

    def instream_file(self, path: str, size: int, timeout: float = 300.0) -> str:
        """Streams exactly `size` bytes: the bytes the caller measured, not whatever the file grew to."""
        def chunks():
            remaining = size
            with open(path, "rb") as fh:
                while remaining > 0:
                    part = fh.read(min(CHUNK, remaining))
                    if not part:
                        raise ClamdError("file shrank while streaming")
                    remaining -= len(part)
                    yield part
        return self._stream(chunks(), timeout)

    def _stream(self, parts, timeout: float) -> str:
        with socket.create_connection(self.addr, timeout=timeout) as s:
            s.sendall(b"zINSTREAM\0")
            for part in parts:
                s.sendall(struct.pack(">I", len(part)))
                s.sendall(part)
            s.sendall(struct.pack(">I", 0))
            return _recv_reply(s)


def _recv_reply(s: socket.socket, limit: int = 64 * 1024) -> str:
    buf = bytearray()
    while len(buf) < limit:
        part = s.recv(4096)
        if not part:
            break
        buf += part
        if buf.endswith(b"\0"):
            break
    return bytes(buf).rstrip(b"\0").decode("utf-8", errors="replace").strip()


def parse_reply(reply: str) -> tuple[str, str | None]:
    """'stream: Win.Test.EICAR_HDB-1 FOUND' -> ('found', name); 'stream: OK' -> ('ok', None)."""
    body = reply.split(":", 1)[1].strip() if reply.startswith("stream:") else reply.strip()
    if body.endswith(" FOUND"):
        name = body[: -len(" FOUND")].strip()
        return ("found", name or "unknown")
    if body == "OK":
        return ("ok", None)
    return ("error", body or "empty reply")


def finding_for(name: str) -> Finding:
    # Heuristic and PUA names are ClamAV's own guesses, not signatures of
    # known malware: they make a file suspicious, never malicious on their own.
    if name.startswith(("Heuristics.", "PUA.")):
        return Finding("clamav", f"clamav.{name.split('.', 2)[0].lower()}", Severity.MEDIUM, f"ClamAV: {name}", 30)
    return Finding("clamav", "clamav.detection", Severity.CRITICAL, f"ClamAV: {name}", 100)


class ClamAVEngine:
    """Owns the clamd process (when it started it) and answers scan requests."""

    def __init__(self, autostart: bool = True, port_: int | None = None) -> None:
        self.client = Clamd(port_=port_)
        self._proc: subprocess.Popen[bytes] | None = None
        self._lock = threading.Lock()
        self._last_check = 0.0
        self._ready = False
        self._version: tuple[float, str | None] | None = None
        self.autostart = autostart

    def status(self) -> str:
        if self.ready():
            return "ready"  # a running clamd has its database loaded
        if install_dir() is None:
            return "not installed"
        return "not running" if has_database() else "no database"

    def ready(self) -> bool:
        # A dead daemon must be noticed, but pinging before every file would
        # double the cost of small scans.
        now = time.monotonic()
        if self._ready and now - self._last_check < 10:
            return True
        self._ready = self.client.ping()
        self._last_check = now
        if not self._ready and self.autostart:
            self.start(wait=0)
        return self._ready

    def start(self, wait: float = 90.0) -> bool:
        with self._lock:
            if self.client.ping():
                self._ready = True
                return True
            d = install_dir()
            if d is None or not has_database():
                return False
            if self._proc is None or self._proc.poll() is not None:
                clamd_conf, _ = write_configs()
                try:
                    self._proc = subprocess.Popen(
                        [str(d / _exe("clamd")), f"--config-file={clamd_conf}"],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        shell=False, creationflags=NO_WINDOW, cwd=str(home()))
                except OSError as e:
                    log.warning("cannot start clamd: %s", e)
                    return False
        deadline = time.monotonic() + wait
        while True:
            if self.client.ping():
                self._ready = True
                self._last_check = time.monotonic()
                return True
            if time.monotonic() >= deadline or (self._proc and self._proc.poll() is not None):
                return False
            time.sleep(1.0)

    def stop(self) -> None:
        with self._lock:
            if self._proc and self._proc.poll() is None:
                try:
                    self.client.command(b"zSHUTDOWN\0", timeout=3)
                    self._proc.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    self._proc.kill()
            self._proc = None
            self._ready = False

    def scan_bytes(self, data: bytes) -> tuple[str, list[Finding]]:
        """Returns (engine status, findings). Never raises."""
        return self._scan(len(data), lambda: self.client.instream(data))

    def scan_file(self, path: str, size: int) -> tuple[str, list[Finding]]:
        if size <= STREAM_MAX_BYTES:
            return self._scan(size, lambda: self.client.instream_file(path, size))
        # Padding an executable past every scanner's size limit is a standard
        # evasion; the code lives at the front, so the front is still checked.
        status, found = self._scan(STREAM_MAX_BYTES, lambda: self.client.instream_file(path, STREAM_MAX_BYTES))
        return (f"partial: first {MAX_FILE_MB} MB clean" if status == "clean" else status), found

    def version(self) -> str | None:
        # "ClamAV 1.5.4/28172/<date>": the daily database number changes with
        # every update, which makes it part of the cache key for old verdicts.
        now = time.monotonic()
        if self._version is not None and now - self._version[0] < 60:
            return self._version[1]
        v = self.client.version() if self.ready() else None
        self._version = (now, v)
        return v

    def _scan(self, size: int, send) -> tuple[str, list[Finding]]:
        if size > STREAM_MAX_BYTES:
            return (f"skipped: larger than {MAX_FILE_MB} MB",
                    [Finding("clamav", "clamav.too_large", Severity.INFO, f"larger than ClamAV's {MAX_FILE_MB} MB limit", 0)])
        if not self.ready():
            return (f"unavailable: {self.status()}", [])
        try:
            reply = send()
        except (OSError, ClamdError) as e:
            self._ready = False
            return (f"error: {e}", [])
        kind, name = parse_reply(reply)
        if kind == "found" and name:
            return ("detected", [finding_for(name)])
        if kind == "ok":
            return ("clean", [])
        return (f"error: {name}", [Finding("clamav", "clamav.error", Severity.INFO, f"ClamAV could not scan: {name}", 0)])
