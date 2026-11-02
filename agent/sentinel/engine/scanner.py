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
from . import defender, filetype, motw
from .signatures import SignatureEngine
from .verdict import CLEAN, Finding, Severity, Verdict

log = logging.getLogger(__name__)

HEAD_BYTES = 64 * 1024


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    # Counter over bytes counts in C; a Python loop is ~20x slower on 1 MB sections.
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


class Scanner:
    def __init__(self, db: Database, *, use_defender: bool = True, signatures: SignatureEngine | None = None) -> None:
        self.db = db
        self.sigs = signatures or SignatureEngine(db)
        self.use_defender = use_defender and defender.available()

    # -- public API --------------------------------------------------------

    def scan_file(self, path: str | os.PathLike[str], *, use_cache: bool = True) -> Verdict:
        p = Path(path)
        name = p.name
        try:
            st = p.stat()
        except OSError as e:
            return Verdict(name=name, sha256="", size=0, path=str(p), skipped=f"unreadable: {e.strerror or e}")
        if not p.is_file():
            return Verdict(name=name, sha256="", size=0, path=str(p), skipped="not a regular file")

        if use_cache:
            cached = self.db.cached_result(str(p), st.st_size, st.st_mtime)
            if cached is not None:
                return _from_dict(cached)

        try:
            sha256, head, body = _read(p, st.st_size)
        except OSError as e:
            return Verdict(name=name, sha256="", size=st.st_size, path=str(p), skipped=f"unreadable: {e.strerror or e}")

        v = self._scan_content(name, sha256, st.st_size, head, body, depth=0)
        v.path = str(p)
        if self.db.is_hash_allowed(sha256):
            v.findings = [Finding("allowlist", "allow.user", Severity.INFO, "trusted by the user", 0)]
            self.db.store_result(str(p), st.st_size, st.st_mtime, v.to_dict())
            return v

        origin = motw.read(str(p))
        if origin is not None:
            v.findings.extend(self._origin_findings(origin, name, head))

        kind = filetype.sniff(head)
        risky_type = filetype.is_executable_kind(kind, name) or kind in ("zip", "rar", "7z", "ole", "pdf")
        if self.use_defender and v.label != "malicious" and (risky_type or v.label != CLEAN):
            v.findings.extend(defender.scan(str(p)))

        self.db.store_result(str(p), st.st_size, st.st_mtime, v.to_dict())
        return v

    def scan_bytes(self, data: bytes, name: str = "<memory>") -> Verdict:
        sha256 = hashlib.sha256(data).hexdigest()
        return self._scan_content(name, sha256, len(data), data[:HEAD_BYTES], data, depth=0)

    # -- internals ---------------------------------------------------------

    def _scan_content(self, name: str, sha256: str, size: int, head: bytes, body: bytes | None, depth: int) -> Verdict:
        v = Verdict(name=name, sha256=sha256, size=size)
        v.findings.extend(self.sigs.match_hash(sha256))
        v.findings.extend(filetype.check_name(name, head))
        if body is None:
            v.skipped = f"larger than {config.MAX_DEEP_SCAN_BYTES // (1024 * 1024)} MB: hash and name checks only"
            return v
        v.findings.extend(self.sigs.match_content(body))
        kind = filetype.sniff(head)
        if kind == "pe":
            v.findings.extend(_pe_structure(body))
        if kind == "zip":
            v.findings.extend(self._scan_zip(name, body, depth))
        return v

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
        out: list[Finding] = []
        if depth >= config.MAX_ARCHIVE_DEPTH:
            return out
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            infos = zf.infolist()
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError, NotImplementedError):
            return out

        names = {i.filename.lower() for i in infos}
        if any(n.endswith("vbaproject.bin") for n in names):
            out.append(Finding("office", "office.macros", Severity.LOW, "Office document contains VBA macros", 15))

        if len(infos) > config.MAX_ARCHIVE_MEMBERS:
            out.append(Finding("archive", "archive.too_many_members", Severity.LOW,
                               f"{len(infos)} members; only the first {config.MAX_ARCHIVE_MEMBERS} inspected", 5))
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
                continue
            sub = self._scan_content(member, hashlib.sha256(content).hexdigest(), len(content),
                                     content[:HEAD_BYTES], content, depth + 1)
            for f in sub.findings:
                if f.severity == Severity.INFO and f.engine == "filetype":
                    continue
                out.append(Finding(f.engine, f.rule, f.severity, f"{info.filename}: {f.detail}", f.score))
        return out


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


def _read(p: Path, size: int) -> tuple[str, bytes, bytes | None]:
    h = hashlib.sha256()
    deep = size <= config.MAX_DEEP_SCAN_BYTES
    chunks: list[bytes] = []
    head = b""
    with p.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            if not head:
                head = chunk[:HEAD_BYTES]
            if deep:
                chunks.append(chunk)
    return h.hexdigest(), head, b"".join(chunks) if deep else None


def _from_dict(d: dict) -> Verdict:
    v = Verdict(name=d["name"], sha256=d["sha256"], size=d["size"], path=d.get("path"), skipped=d.get("skipped"))
    for f in d.get("findings", []):
        v.findings.append(Finding(f["engine"], f["rule"], Severity[f["severity"]], f["detail"], f["score"]))
    return v
