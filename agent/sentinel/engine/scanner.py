"""Scan orchestrator: combines every engine into one Verdict per file."""

from __future__ import annotations

import hashlib
import io
import logging
import math
import os
import zipfile
from collections import Counter
from pathlib import Path

from .. import config, urlintel
from ..db import Database
from . import clamav, defender, filetype, motw
from .clamav import ClamAVEngine
from .signatures import SignatureEngine
from .verdict import CLEAN, MALICIOUS, Finding, Severity, Verdict

log = logging.getLogger(__name__)

HEAD_BYTES = 64 * 1024
TAIL_BYTES = 8 * 1024 * 1024
INFLATED_PE_BYTES = 100 * 1024 * 1024


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    # Counter over bytes counts in C; a Python loop is ~20x slower on 1 MB sections.
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


class Scanner:
    """The scan gate: every file passes through each layer in turn —
    Sentinel core (hash, names, structure, archives) → rule packs and YARA-X →
    ClamAV → Microsoft Defender — and the verdict records what each layer said."""

    def __init__(self, db: Database, *, use_defender: bool = True, use_clamav: bool = False,
                 clamav_engine: ClamAVEngine | None = None, signatures: SignatureEngine | None = None) -> None:
        self.db = db
        self.sigs = signatures or SignatureEngine(db)
        self.use_defender = use_defender and defender.available()
        if clamav_engine is None and use_clamav and clamav.install_dir() is not None:
            clamav_engine = ClamAVEngine()
        self.clamav = clamav_engine

    def gate_id(self) -> str:
        """Identifies the engines and signature versions behind a verdict: a
        cached "clean" from before ClamAV's last update is not reused."""
        parts = [f"rules:{len(self.sigs.pattern_rules)}", f"yara:{self.sigs.yara_rules}"]
        if self.clamav is not None:
            parts.append(f"clamav:{self.clamav.version() or 'down'}")
        parts.append(f"defender:{int(self.use_defender)}")
        return "|".join(parts)

    # -- public API --------------------------------------------------------

    def scan_file(self, path: str | os.PathLike[str], *, use_cache: bool = True) -> Verdict:
        p = Path(os.path.realpath(path))
        name = p.name
        try:
            st = p.stat()
        except OSError as e:
            return Verdict(name=name, sha256="", size=0, path=str(p), skipped=f"unreadable: {e.strerror or e}")
        if not p.is_file():
            return Verdict(name=name, sha256="", size=0, path=str(p), skipped="not a regular file")

        try:
            sha256, head, body = _read(p, st.st_size, st.st_mtime)
        except FileChanged:
            return Verdict(name=name, sha256="", size=st.st_size, path=str(p), skipped="changed while scanning")
        except OSError as e:
            return Verdict(name=name, sha256="", size=st.st_size, path=str(p), skipped=f"unreadable: {e.strerror or e}")

        gate = self.gate_id()
        if use_cache:
            # Size and timestamps are under the control of whoever wrote the
            # file (os.utime restores an old mtime after a same-size swap), so
            # a cached verdict is reused only for the very same bytes.
            cached = self.db.cached_result(str(p), st.st_size, st.st_mtime, st.st_ino)
            if cached is not None and cached.get("gate") == gate and cached.get("sha256") == sha256:
                return _from_dict(cached)

        if self.db.is_hash_allowed(sha256):
            v = Verdict(name=name, sha256=sha256, size=st.st_size, path=str(p),
                        findings=[Finding("allowlist", "allow.user", Severity.INFO, "trusted by the user", 0)],
                        engines={"allowlist": "trusted by the user"})
            self._store(p, st, v, gate)
            return v

        v = self._scan_content(name, sha256, st.st_size, head, body, depth=0)
        v.path = str(p)
        if body is None:
            v.findings.extend(self._scan_oversized(p, st.st_size, head, v))
        if body is None and filetype.sniff(head) == "zip":
            # Too big to hold in memory, but each member can still be inspected
            # straight from disk.
            try:
                with p.open("rb") as fh:
                    refusal = _zip_directory_refusal(fh)
                    if refusal:
                        v.findings.append(refusal)
                    else:
                        with zipfile.ZipFile(fh) as zf:
                            v.findings.extend(self._scan_zip_members(name, zf, depth=0))
                        v.skipped = None
            except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError, NotImplementedError):
                pass

        origin = motw.read(str(p))
        if origin is not None:
            v.findings.extend(self._origin_findings(origin, name, head))

        if self.clamav is not None:
            if body is not None:
                status, found = self.clamav.scan_bytes(body)
            else:
                status, found = self.clamav.scan_file(str(p), st.st_size)
                try:
                    st2 = p.stat()
                    if (st2.st_size, st2.st_mtime) != (st.st_size, st.st_mtime):
                        status, found = "error: file changed while streaming", []
                except OSError:
                    status, found = "error: file vanished while streaming", []
            v.engines["clamav"] = status
            v.findings.extend(found)

        kind = filetype.sniff(head)
        risky_type = filetype.is_executable_kind(kind, name) or kind in ("zip", "rar", "7z", "gzip", "ole", "pdf")
        if not self.use_defender:
            v.engines["defender"] = "unavailable: off or not the active antivirus"
        elif v.label == MALICIOUS:
            v.engines["defender"] = "skipped: already detected"
        elif risky_type or v.label != CLEAN:
            found = defender.scan(str(p))
            v.engines["defender"] = "detected" if found else "clean"
            v.findings.extend(found)
        else:
            v.engines["defender"] = "skipped: not a risky file type"

        self._store(p, st, v, gate)
        return v

    def scan_bytes(self, data: bytes, name: str = "<memory>") -> Verdict:
        sha256 = hashlib.sha256(data).hexdigest()
        v = self._scan_content(name, sha256, len(data), data[:HEAD_BYTES], data, depth=0)
        if self.clamav is not None:
            status, found = self.clamav.scan_bytes(data)
            v.engines["clamav"] = status
            v.findings.extend(found)
        return v

    # -- internals ---------------------------------------------------------

    def _store(self, p: Path, st: os.stat_result, v: Verdict, gate: str) -> None:
        self.db.store_result(str(p), st.st_size, st.st_mtime, st.st_ino, {**v.to_dict(), "gate": gate})

    def _scan_content(self, name: str, sha256: str, size: int, head: bytes, body: bytes | None, depth: int) -> Verdict:
        v = Verdict(name=name, sha256=sha256, size=size)
        v.findings.extend(self.sigs.match_hash(sha256))
        v.findings.extend(filetype.check_name(name, head))
        if body is None:
            v.skipped = f"larger than {config.MAX_DEEP_SCAN_BYTES // (1024 * 1024)} MB: hash and name checks only"
            v.engines["sentinel"] = _layer_status(v.findings, ("signature", "filetype"), partial=True)
            v.engines["rules+yara"] = "skipped: file too large"
            return v
        v.findings.extend(self.sigs.match_content(body))
        kind = filetype.sniff(head)
        if kind == "pe":
            v.findings.extend(_pe_structure(body))
        if kind == "zip":
            v.findings.extend(self._scan_zip(name, body, depth))
        v.engines["sentinel"] = _layer_status(v.findings, ("signature", "filetype", "pe", "archive", "office"))
        v.engines["rules+yara"] = (_layer_status(v.findings, ("rules", "yara"))
                                   if self.sigs.pattern_rules or self.sigs.yara_rules else "unavailable: no rules installed")
        return v

    def _scan_oversized(self, p: Path, size: int, head: bytes, v: Verdict) -> list[Finding]:
        """Too big to hold in memory: rules and YARA still see the first and
        last parts, where droppers keep their code and appended payloads."""
        out: list[Finding] = []
        tail_len = min(TAIL_BYTES, max(0, size - config.MAX_DEEP_SCAN_BYTES))
        try:
            with p.open("rb") as fh:
                front = fh.read(config.MAX_DEEP_SCAN_BYTES)
                fh.seek(size - tail_len)
                tail = fh.read(tail_len)
        except OSError:
            return out
        seen: set[str] = set()
        for part in (front, tail):
            for f in self.sigs.match_content(part):
                if f.rule not in seen:
                    seen.add(f.rule)
                    out.append(f)
        if filetype.sniff(head) == "pe":
            out.extend(f for f in _pe_structure(front) if f.rule != "pe.malformed")
            # Hundreds of MB of near-constant bytes after the code is padding
            # meant to exceed scanners' size limits; real installers append
            # compressed (high-entropy) data instead.
            if size > INFLATED_PE_BYTES and tail and entropy(tail[-1024 * 1024:]) < 1.0:
                out.append(Finding("pe", "pe.inflated", Severity.MEDIUM,
                                   f"executable padded to {size // (1024 * 1024)} MB with filler bytes "
                                   "(a trick to exceed antivirus size limits)", 35))
        v.engines["rules+yara"] = (("detected" if any(f.engine in ("rules", "yara") for f in out) else
                                    "partial: first 64 MB and last 8 MB clean")
                                   if self.sigs.pattern_rules or self.sigs.yara_rules else "unavailable: no rules installed")
        return out

    def _origin_findings(self, origin: motw.Origin, name: str, head: bytes) -> list[Finding]:
        out: list[Finding] = []
        for url in (origin.host_url, origin.referrer_url):
            if not url:
                continue
            rep = urlintel.check(self.db, url)
            if rep["verdict"] == "malicious":
                out.append(Finding("origin", "origin.blocklisted_source", Severity.HIGH,
                                   f"downloaded from a {rep['kind']} source listed by {rep['source']}: {rep['matched']}", 50))
                break
        if origin.from_internet and filetype.is_executable_kind(filetype.sniff(head), name):
            out.append(Finding("origin", "origin.internet_executable", Severity.INFO,
                               "executable downloaded from the internet", 0))
        return out

    def _scan_zip(self, name: str, data: bytes, depth: int) -> list[Finding]:
        if depth >= config.MAX_ARCHIVE_DEPTH:
            return [Finding("archive", "archive.depth_limit", Severity.INFO,
                            f"nested archives deeper than {config.MAX_ARCHIVE_DEPTH} levels were not opened", 0)]
        buf = io.BytesIO(data)
        refusal = _zip_directory_refusal(buf)
        if refusal:
            return [refusal]
        try:
            zf = zipfile.ZipFile(buf)
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError, NotImplementedError):
            return []
        return self._scan_zip_members(name, zf, depth)

    def _scan_zip_members(self, name: str, zf: zipfile.ZipFile, depth: int) -> list[Finding]:
        out: list[Finding] = []
        try:
            infos = zf.infolist()
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError, NotImplementedError):
            return out
        # Executables and scripts first, so the member limit never hides them
        # behind thousands of harmless entries.
        infos = sorted(infos, key=lambda i: filetype.extension(i.filename) not in filetype.EXECUTABLE_EXTS
                       and filetype.extension(i.filename) not in filetype.ARCHIVE_EXTS)

        names = {i.filename.lower() for i in infos}
        if any(n.endswith("vbaproject.bin") for n in names):
            out.append(Finding("office", "office.macros", Severity.LOW, "Office document contains VBA macros", 15))

        if len(infos) > config.MAX_ARCHIVE_MEMBERS:
            out.append(Finding("archive", "archive.too_many_members", Severity.LOW,
                               f"{len(infos)} members; only the first {config.MAX_ARCHIVE_MEMBERS} inspected", 5))
            # Names cost nothing to check: deceptive names past the limit are still reported.
            for info in infos[config.MAX_ARCHIVE_MEMBERS:]:
                for f in filetype.check_name(info.filename, b""):
                    if f.severity > Severity.INFO:
                        out.append(Finding(f.engine, f.rule, f.severity, f"{info.filename}: {f.detail}", f.score))
        total = 0
        for info in infos[: config.MAX_ARCHIVE_MEMBERS]:
            if info.is_dir():
                continue
            member = f"{name}!{info.filename}"
            if info.flag_bits & 0x1:
                if filetype.extension(info.filename) in filetype.EXECUTABLE_EXTS:
                    out.append(Finding("archive", "archive.encrypted_executable", Severity.MEDIUM,
                                       f"password-protected archive hides executable '{info.filename}'", 30))
                continue
            if info.compress_size and info.file_size / info.compress_size > 200 and info.file_size > 50 * 1024 * 1024:
                out.append(Finding("archive", "archive.bomb", Severity.MEDIUM,
                                   f"'{info.filename}' expands {info.file_size // info.compress_size}x (decompression bomb)", 30))
                continue
            total += info.file_size
            if total > config.MAX_ARCHIVE_TOTAL_BYTES:
                out.append(Finding("archive", "archive.size_limit", Severity.INFO, "archive larger than inspection limit", 0))
                break
            try:
                with zf.open(info) as fh:
                    content = fh.read(config.MAX_DEEP_SCAN_BYTES + 1)
            except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError, NotImplementedError):
                continue
            if len(content) > config.MAX_DEEP_SCAN_BYTES:
                out.append(Finding("archive", "archive.member_too_large", Severity.INFO,
                                   f"'{info.filename}' is larger than the inspection limit", 0))
                continue
            sub = self._scan_content(member, hashlib.sha256(content).hexdigest(), len(content),
                                     content[:HEAD_BYTES], content, depth + 1)
            for f in sub.findings:
                if f.severity == Severity.INFO and f.engine == "filetype":
                    continue
                out.append(Finding(f.engine, f.rule, f.severity, f"{info.filename}: {f.detail}", f.score))
        return out


MAX_ZIP_ENTRIES = 200_000
MAX_ZIP_DIRECTORY_BYTES = 32 * 1024 * 1024


def _zip_directory_refusal(fh) -> Finding | None:
    """Read the end-of-central-directory record before zipfile parses the
    whole directory: a small archive declaring millions of entries would
    otherwise exhaust memory before any member limit applies."""
    try:
        fh.seek(0, io.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - 66_000))
        tail = fh.read()
        fh.seek(0)
    except OSError:
        return None
    i = tail.rfind(b"PK\x05\x06")
    if i < 0 or i + 22 > len(tail):
        return None  # not found: let zipfile decide (it will reject a broken archive)
    entries = int.from_bytes(tail[i + 10:i + 12], "little")
    dir_size = int.from_bytes(tail[i + 12:i + 16], "little")
    z64 = tail.rfind(b"PK\x06\x06", 0, i)  # ZIP64 record carries the real 64-bit counts
    if z64 >= 0 and z64 + 56 <= len(tail):
        entries = int.from_bytes(tail[z64 + 32:z64 + 40], "little")
        dir_size = int.from_bytes(tail[z64 + 40:z64 + 48], "little")
    if entries > MAX_ZIP_ENTRIES or dir_size > MAX_ZIP_DIRECTORY_BYTES:
        return Finding("archive", "archive.directory_too_large", Severity.LOW,
                       f"archive declares {entries} entries / {dir_size} directory bytes; not opened", 10)
    return None


def _pe_structure(data: bytes) -> list[Finding]:
    """Generic structure signals; deliberately weak so ordinary installers stay clean."""
    out: list[Finding] = []
    try:
        if len(data) < 0x40:
            return [Finding("pe", "pe.truncated", Severity.LOW, "truncated executable header", 10)]
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if e_lfanew <= 0 or e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return [Finding("pe", "pe.malformed", Severity.LOW, "MZ header without a valid PE header", 10)]
        n_sections = int.from_bytes(data[e_lfanew + 6:e_lfanew + 8], "little")
        opt_size = int.from_bytes(data[e_lfanew + 20:e_lfanew + 22], "little")
        opt = e_lfanew + 24
        magic = int.from_bytes(data[opt:opt + 2], "little")
        dd_off = opt + (96 if magic == 0x10B else 112)
        sec_table = opt + opt_size
        # Data directory 4 is the Authenticode certificate table.
        sec_dir = dd_off + 4 * 8
        signed = sec_dir + 8 <= len(data) and int.from_bytes(data[sec_dir + 4:sec_dir + 8], "little") > 0
        end_of_sections = 0
        high_entropy_exec = False
        for i in range(min(n_sections, 96)):
            s = sec_table + 40 * i
            if s + 40 > len(data):
                break
            raw_size = int.from_bytes(data[s + 16:s + 20], "little")
            raw_ptr = int.from_bytes(data[s + 20:s + 24], "little")
            chars = int.from_bytes(data[s + 36:s + 40], "little")
            end_of_sections = max(end_of_sections, raw_ptr + raw_size)
            if chars & 0x20000000 and raw_size > 4096:  # IMAGE_SCN_MEM_EXECUTE
                if entropy(data[raw_ptr:raw_ptr + min(raw_size, 1 << 20)]) > 7.4:
                    high_entropy_exec = True
        if high_entropy_exec:
            out.append(Finding("pe", "pe.packed", Severity.LOW, "executable code section is compressed or encrypted", 10))
        if not signed:
            out.append(Finding("pe", "pe.unsigned", Severity.INFO, "no Authenticode signature", 0))
        if high_entropy_exec and not signed:
            out.append(Finding("pe", "pe.packed_unsigned", Severity.LOW, "packed and unsigned", 10))
    except Exception:
        out.append(Finding("pe", "pe.malformed", Severity.LOW, "executable header could not be parsed", 10))
    return out


class FileChanged(Exception):
    """The file was modified while being read; the watcher will rescan it."""


def _read(p: Path, size: int, mtime: float) -> tuple[str, bytes, bytes | None]:
    h = hashlib.sha256()
    deep = size <= config.MAX_DEEP_SCAN_BYTES
    chunks: list[bytes] = []
    head = b""
    remaining = size  # never read past the size we stat'ed, even if the file keeps growing
    with p.open("rb") as f:
        while remaining > 0:
            chunk = f.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            h.update(chunk)
            if not head:
                head = chunk[:HEAD_BYTES]
            if deep:
                chunks.append(chunk)
    st = p.stat()
    if remaining or st.st_size != size or st.st_mtime != mtime:
        raise FileChanged(str(p))
    return h.hexdigest(), head, b"".join(chunks) if deep else None


def _layer_status(findings: list[Finding], engines: tuple[str, ...], partial: bool = False) -> str:
    hits = [f for f in findings if f.engine in engines and f.severity >= Severity.MEDIUM]
    if hits:
        return "detected"
    return "clean (hash and name only)" if partial else "clean"


def _from_dict(d: dict) -> Verdict:
    engines = d.get("engines") if isinstance(d.get("engines"), dict) else {}
    v = Verdict(name=d["name"], sha256=d["sha256"], size=d["size"], path=d.get("path"), skipped=d.get("skipped"),
                engines={str(k): str(s) for k, s in engines.items()})
    for f in d.get("findings", []):
        v.findings.append(Finding(f["engine"], f["rule"], Severity[f["severity"]], f["detail"], f["score"]))
    return v
