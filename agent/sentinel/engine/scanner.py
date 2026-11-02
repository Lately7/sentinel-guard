"""The scan gate as callers know it: Scanner, over Gate v2 (R11 §3 "Compatibility adapter").

Every file goes through core, rules and YARA-X, ClamAV and Defender in turn. This
module only decides which stages apply to this file on this machine and projects
the typed decision back into the Verdict that callers read.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass

from .. import config, urlintel
from ..db import Database
from ..gate_v2 import cache, legacy
from ..gate_v2.actions import ProtectionBarrier
from ..gate_v2.analyzers.lnk import LnkAdapter
from ..gate_v2.analyzers.motw import MotwAdapter
from ..gate_v2.analyzers.signer import SignerAdapter
from ..gate_v2.clamd import ClamdAdapter
from ..gate_v2.contract import (
    CONTRACT_VERSION, EVIDENCE_POLICY_VERSION, LEGACY_POLICY_VERSION, EngineAdapter,
    FileIdentity, FinalDecision, ScanRequest, VerdictCode,
)
from ..gate_v2.core import CoreAdapter
from ..gate_v2.defender import DefenderAdapter
from ..gate_v2.orchestrator import scan as run_gate
from ..gate_v2.policy import RequiredStages
from ..gate_v2.rules import JsonRulesAdapter, YaraXAdapter
from . import clamav, defender, filetype
from .clamav import ClamAVEngine
from .signatures import SignatureEngine
from .verdict import Finding, Severity

log = logging.getLogger(__name__)

HEAD_BYTES = 64 * 1024
# Analyzers add context; they are never what makes a file clean.
ANALYZER_VERSIONS = (("lnk", "1"), ("signer", "1"), ("motw", "1"))


@dataclass
class _Plan:
    adapters: list[EngineAdapter]
    stages: RequiredStages
    defaults: dict[str, str]
    inputs: cache.GenerationInputs


class Scanner:
    def __init__(self, db: Database, *, use_defender: bool = True, use_clamav: bool = False,
                 clamav_engine: ClamAVEngine | None = None, signatures: SignatureEngine | None = None,
                 defender_runner: defender.Runner | None = None) -> None:
        self.db = db
        self._sigs = signatures or SignatureEngine(db)
        self.want_defender = use_defender
        if clamav_engine is None and use_clamav and clamav.install_dir() is not None:
            clamav_engine = ClamAVEngine()
        self.clamav = clamav_engine
        self._lock = threading.Lock()
        self._rules: tuple[JsonRulesAdapter, YaraXAdapter] | None = None
        self._clamd: ClamdAdapter | None = None
        self._defender = DefenderAdapter(applicability=self._defender_state,
                                         runner=_adapt_runner(defender_runner) if defender_runner else _default_runner())

    @property
    def sigs(self) -> SignatureEngine:
        return self._sigs

    @sigs.setter
    def sigs(self, value: SignatureEngine) -> None:
        # New rules arrived: the compiled adapters are stale.
        with self._lock:
            self._sigs = value
            self._rules = None

    @property
    def use_defender(self) -> bool:
        # Re-evaluated (with a TTL) so a Defender that becomes active or passive
        # while the agent runs is picked up without a restart.
        return self.want_defender and defender.available()

    @staticmethod
    def _defender_state(deadline_ns: int | None) -> tuple[str | None, str]:
        return defender.mpcmdrun_path(), "active" if defender.available() else "passive"

    def _rule_adapters(self) -> tuple[JsonRulesAdapter, YaraXAdapter]:
        with self._lock:
            if self._rules is None:
                packs = JsonRulesAdapter.from_directories(config.user_rules_dir(), tuple(self._sigs.bundled_dirs))
                self._rules = (packs, YaraXAdapter(self._sigs.yara_sources()))
            return self._rules

    def _clamd_adapter(self) -> ClamdAdapter:
        if self._clamd is None:
            engine = self.clamav
            assert engine is not None
            self._clamd = ClamdAdapter(port=engine.client.addr[1], verifier=engine.verify, facts=engine.facts,
                                       stream_cap=clamav.STREAM_MAX_BYTES)
        return self._clamd

    def _known_bad(self, digest: str) -> str | None:
        row = self.db.hash_info(digest)
        return (row["source"] or "known-bad") if row else None

    def _origin_listed(self, url: str) -> bool:
        return urlintel.check(self.db, url)["verdict"] == "malicious"

    def _plan(self, name: str, head: bytes, has_path: bool) -> _Plan:
        packs, compiled = self._rule_adapters()
        adapters: list[EngineAdapter] = [CoreAdapter(self._known_bad, name)]
        required = {"core"}
        defaults: dict[str, str] = {}
        digests: list[tuple[str, str]] = []
        if packs.rules:
            adapters.append(packs)
            required.add("json_rules")
            digests.append(("json_rules", packs.ruleset_digest))
        if compiled.readiness() != "YARA_UNAVAILABLE":
            adapters.append(compiled)
            required.add("yara_x")
            digests.append(("yara_x", compiled.ruleset_digest))
        if not digests:
            defaults["rules+yara"] = "unavailable: no rules installed"

        clamav_state, clamav_generation = "not_installed", None
        if self.clamav is not None:
            # Configured but down is still required: that file was not checked, so
            # it cannot be clean (RT-013). Nothing is sent to a daemon that is down.
            required.add("clamav")
            if self.clamav.ready():
                gate = self._clamd_adapter()
                adapters.append(gate)
                readiness = gate.readiness()
                clamav_state = "verified" if readiness.trusted else "unavailable"
                clamav_generation = readiness.generation_digest
            else:
                clamav_state = "unavailable"
                defaults["clamav"] = f"unavailable: {self.clamav.status()}"

        kind = filetype.sniff(head)
        risky = filetype.is_executable_kind(kind, name) or kind in ("zip", "rar", "7z", "gzip", "ole", "pdf")
        defender_state = "active" if self.use_defender else "passive"
        if defender_state != "active":
            defaults["defender"] = "unavailable: off or not the active antivirus"
        elif has_path and risky:
            # One MpCmdRun takes seconds, so it is kept for what is worth a second opinion.
            adapters.append(self._defender)
            required.add("defender")
        else:
            defaults["defender"] = "skipped: not a risky file type"

        adapters += [LnkAdapter(), SignerAdapter(), MotwAdapter(url_check=self._origin_listed)]
        generation = str(self.db.generation())
        inputs = cache.GenerationInputs(
            EVIDENCE_POLICY_VERSION, CONTRACT_VERSION, "core-v2", ANALYZER_VERSIONS, tuple(digests),
            generation, clamav_generation, clamav_state, defender_state, generation, ())
        return _Plan(adapters, RequiredStages(frozenset(required)), defaults, inputs)

    def gate_id(self) -> str:
        """Identifies the engines and signature contents behind a verdict."""
        return cache.gate_generation(self._plan("", b"", True).inputs)

    # -- public API --------------------------------------------------------

    def scan_file(self, path: str | os.PathLike[str], *, use_cache: bool = True,
                  barrier: ProtectionBarrier | None = None) -> legacy.GateVerdict:
        real = os.path.realpath(path)
        try:
            with open(real, "rb") as stream:
                head = stream.read(HEAD_BYTES)
        except OSError:
            head = b""  # the gate reports why, through its own open
        return self._scan(os.path.basename(real), real, None, head, use_cache, barrier)

    def scan_bytes(self, data: bytes, name: str = "<memory>") -> legacy.GateVerdict:
        return self._scan(name, None, data, data[:HEAD_BYTES], False)

    # -- internals ---------------------------------------------------------

    def _scan(self, name: str, path: str | None, data: bytes | None, head: bytes, use_cache: bool,
              barrier: ProtectionBarrier | None = None) -> legacy.GateVerdict:
        plan = self._plan(name, head, path is not None)
        generation = cache.gate_generation(plan.inputs)
        request = ScanRequest(CONTRACT_VERSION, uuid.uuid4().hex, "file", path, data, "on_demand",
                              "single_file" if path else "memory", EVIDENCE_POLICY_VERSION,
                              LEGACY_POLICY_VERSION,
                              time.monotonic_ns() + int(config.SCAN_DEADLINE_SECONDS * 1e9),
                              barrier.stamp() if barrier else None, use_cache)
        served: list[str] = []

        def known(measured: FileIdentity) -> FinalDecision | None:
            if path is None:
                return None
            if self.db.is_hash_allowed(measured.sha256) or self.db.has_restore_exception(path, measured.sha256):
                served.append("allowlist")
                return _trusted(request, measured, generation)
            found = cache.lookup(self.db, measured, generation, request, time.time())
            if found is not None:
                served.append("cache")
            return found

        decision = run_gate(request, adapters=plan.adapters, stages=plan.stages, gate_generation=generation,
                            auto_quarantine=True, max_bytes=config.MAX_SCAN_BYTES,
                            resident_limit=config.MAX_DEEP_SCAN_BYTES, short_circuit=known,
                            current_protection_generation=barrier.current if barrier else None)
        if not served:
            cache.store(self.db, decision, time.time())
        verdict = legacy.project(decision, name=name, path=path, stage_defaults=plan.defaults)
        if "allowlist" in served:
            verdict.findings = [Finding("allowlist", "allow.user", Severity.INFO, "trusted by the user", 0)]
            verdict.engines = {"allowlist": "trusted by the user"}
            verdict.reset_projection()
        return verdict


def _trusted(request: ScanRequest, measured: FileIdentity, generation: str) -> FinalDecision:
    # Not a scan result: nothing looked at these bytes, so it is never trusted clean.
    return FinalDecision(CONTRACT_VERSION, request.scan_id, request.file_id, measured, VerdictCode.CLEAN,
                         False, "reduced", ("USER_TRUST",), (), (), False, generation, 0)


def _default_runner():
    from ..gate_v2.defender import _run

    return _run


def _adapt_runner(runner: defender.Runner):
    """Tests inject the old (argv, timeout) runner."""
    def adapted(argv: list[str], deadline_ns: int, cancel: object) -> tuple[int, str]:
        return runner(argv, max(0.0, (deadline_ns - time.monotonic_ns()) / 1e9))
    return adapted
