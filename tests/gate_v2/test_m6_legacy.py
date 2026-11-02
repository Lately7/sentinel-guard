"""Legacy projection tests with synthetic structured evidence only."""

from dataclasses import replace
import json

from sentinel.engine.verdict import Finding, Severity, Verdict
from sentinel.gate_v2.contract import (
    ByteRange, Category, Coverage, EngineResult, Evidence, FileIdentity,
    FinalDecision, ScanRequest, StageStatus, Strength, VerdictCode,
)
from sentinel.gate_v2.legacy import UNKNOWN, GateVerdict, project
from sentinel.gate_v2.policy import RequiredStages, decide


def request():
    return ScanRequest(2, "scan", "file", None, b"abc", "test", "memory",
                       "evidence-v1", "legacy-v0", 10**18, None, True)


def identity():
    return FileIdentity("C:/sample", 3, "a" * 32, 3, "b" * 64, 5, 7)


def evidence(engine="core", code="EICAR", strength=Strength.CONCLUSIVE,
             *, name=None, member=None, identifier=None):
    return Evidence("e-" + engine + code, engine, identifier or code, name,
                    Category.MALWARE, strength, "member" if member else "outer",
                    member, (ByteRange(0, 1),), "test", None, None, True, code)


def result(engine="core", status=StageStatus.COMPLETED, *, code="READY", hits=(), mode="full"):
    spans = (ByteRange(0, 3),) if mode == "full" else (ByteRange(0, 2),) if mode == "fixed_partial" else ()
    coverage = Coverage(3, spans, mode, 0, 0, 0, 0, (), (), (), "verified")
    return EngineResult(2, engine, "file", identity(), status, VerdictCode.UNKNOWN,
                        coverage, tuple(hits), "1", None, None, code, 0, 1, None)


def decision(*results, disabled=()):
    return decide(tuple(results), request(), "gate", stages=RequiredStages(
        frozenset(item.engine_id for item in results), frozenset(disabled)))


def projected(*results, disabled=(), defaults=None):
    return project(decision(*results, disabled=disabled), name="sample.bin",
                   path="C:/sample", stage_defaults=defaults or {})


def test_old_keys_scan_result_and_unknown_label():
    v = projected(result("core"), result("json_rules"), result("yara_x"),
                  result("defender"), defaults={"clamav": "unavailable: off or not the active antivirus"})
    assert isinstance(v, Verdict) and isinstance(v, GateVerdict)
    assert set(v.engines) == {"sentinel", "rules+yara", "clamav", "defender"}
    assert v.engines["sentinel"] == v.engines["rules+yara"] == "clean"
    old = {"name", "path", "sha256", "size", "score", "label", "skipped",
           "engines", "findings", "findings_total"}
    assert set(v.to_dict()) == old | {"scan_result"}
    summary = v.to_dict()["scan_result"]
    assert summary["contract_version"] == 2 and summary["trusted_clean"]
    assert summary["stages"][0] == {"engine_id": "core", "status": "completed",
                                    "verdict": "unknown", "readiness_code": "READY",
                                    "coverage_mode": "full"}
    assert "C:/sample" not in json.dumps(summary)
    assert "clamav" not in projected(result()).engines
    unknown = projected(result(status=StageStatus.ERROR, mode="none"))
    assert unknown.label == UNKNOWN and unknown.skipped.startswith("incomplete:")
    assert unknown.sha256 == identity().sha256 and unknown.score == 0


def test_stage_status_table_and_prefixes():
    cases = (
        (StageStatus.COMPLETED, "READY", (), "clean"),
        (StageStatus.COMPLETED, "READY", (evidence(strength=Strength.SUPPORTING),), "detected"),
        (StageStatus.PARTIAL, "LIMIT", (), "partial: limit"),
        (StageStatus.SKIPPED, "CONCLUSIVE_HIT", (), "skipped: already detected"),
        (StageStatus.SKIPPED, "NOT_RISKY", (), "skipped: not_risky"),
        (StageStatus.UNAVAILABLE, "OFF", (), "unavailable: off"),
        (StageStatus.UNVERIFIED, "BAD_DAEMON", (), "unavailable: unverified daemon"),
        (StageStatus.ERROR, "FAILED", (), "error: failed"),
        (StageStatus.CHANGED, "CHANGED", (), "error: changed"),
        (StageStatus.TIMEOUT, "DEADLINE", (), "timeout: deadline"),
        (StageStatus.CANCELLED, "CANCELLED", (), "skipped: cancelled"),
    )
    for status, code, hits, expected in cases:
        mode = "full" if status is StageStatus.COMPLETED else "fixed_partial" if status is StageStatus.PARTIAL else "none"
        v = projected(result(status=status, code=code, hits=hits, mode=mode))
        assert v.engines["sentinel"] == expected
        assert v.engines["sentinel"].startswith(expected.split(":", 1)[0])
    v = projected(result("json_rules", hits=(evidence("json_rules", "RULE", Strength.SUPPORTING),)),
                  result("yara_x", status=StageStatus.ERROR, mode="none"))
    assert v.engines["rules+yara"] == "detected"


def test_skipped_reason_table_and_identity_failures():
    base = decision(result())
    cases = {
        "CHANGED": "changed while scanning", "IN_USE": "unreadable: in use by another program",
        "UNREADABLE": "unreadable: cannot open", "NOT_REGULAR": "not a regular file",
        "TOO_LARGE": "too large to scan", "CANCELLED": "cancelled",
        "ENGINE_TIMEOUT": "incomplete: engine_timeout",
        "MISSING_STAGE": "incomplete: missing_stage",
        "UNBOUND_EVIDENCE": "incomplete: unbound_evidence",
        "UNVERIFIED_ENGINE": "incomplete: unverified_engine",
        "ENGINE_INCOMPLETE": "incomplete: engine_incomplete",
        "INCOMPLETE_COVERAGE": "incomplete: incomplete_coverage",
        "UNCERTAIN_COVERAGE": "incomplete: uncertain_coverage",
        "UNACCEPTED_DETECTION": "incomplete: unaccepted_detection",
        "ADMISSION_FULL": "incomplete: admission_full",
    }
    for reason, expected in cases.items():
        unknown = replace(base, identity=None, engine_results=(), verdict=VerdictCode.UNKNOWN,
                          trusted_clean=False, cacheable=False, reason_codes=(reason,))
        v = project(unknown, name="missing", path="C:/missing", stage_defaults={})
        assert v.label == UNKNOWN and v.sha256 == "" and v.size == 0
        assert v.skipped == expected
    for reason in ("FIXED_PARTIAL", "REDUCED_POLICY"):
        reduced = replace(base, trusted_clean=False, policy_scope="reduced", reason_codes=(reason,))
        assert project(reduced, name="sample", path=None, stage_defaults={}).skipped == f"partial: {reason.lower()}"
    for hit in (None, evidence(strength=Strength.SUPPORTING), evidence()):
        v = projected(result(hits=(hit,) if hit else ()))
        assert v.skipped is None


def test_finding_mapping_strengths_and_appended_critical():
    cases = (
        ("core", "EICAR", None, None, "signature", "eicar.test_file"),
        ("core", "KNOWN_BAD_HASH", None, None, "signature", "hash.known_bad"),
        ("core", "RTLO", None, None, "filetype", "filetype.rtlo"),
        ("core", "DOUBLE_EXTENSION", None, None, "filetype", "filetype.double_extension"),
        ("core", "PADDED_NAME", None, None, "filetype", "filetype.padded_name"),
        ("core", "MISMATCH", None, None, "filetype", "filetype.mismatch"),
        ("core", "PE_PACKED_SECTION", None, None, "pe", "pe.packed_section"),
        ("core", "SCRIPT_INDICATOR", None, None, "script", "script.indicator"),
        ("json_rules", "RULE", None, "my.rule", "rules", "my.rule"),
        ("yara_x", "RULE", "ns.rule", "rule", "yara", "yara.rule"),
        ("clamav", "CLAMD_FOUND", "Trojan.Generic", None, "clamav", "clamav.detection"),
        ("defender", "THREAT", "Example", None, "defender", "defender.detection"),
        ("lnk", "MACRO", None, None, "lnk", "lnk.macro"),
    )
    for engine, code, name, identifier, expected_engine, expected_rule in cases:
        hit = evidence(engine, code, name=name, identifier=identifier)
        v = projected(result(engine, hits=(hit,)))
        finding = v.findings[0]
        assert (finding.engine, finding.rule) == (expected_engine, expected_rule)
        assert finding.severity is Severity.CRITICAL and finding.score == 100
    weak = projected(result("clamav", hits=(evidence("clamav", "CLAMD_FOUND", Strength.SUPPORTING,
                                                     name="PUA.Example", member="member.bin"),)))
    assert weak.findings[0].rule == "clamav.pua"
    assert weak.findings[0].detail.startswith("member.bin: ClamAV: PUA.Example")
    assert weak.findings[0].severity is Severity.MEDIUM and weak.findings[0].score == 30
    for strength, severity, score in ((Strength.STRONG, Severity.HIGH, 50),
                                      (Strength.CONTEXT, Severity.INFO, 0),
                                      (Strength.COVERAGE, Severity.INFO, 0)):
        v = projected(result(hits=(evidence(strength=strength),)))
        assert (v.findings[0].severity, v.findings[0].score) == (severity, score)
    rtlo = projected(result(hits=(evidence(code="RTLO", strength=Strength.SUPPORTING),)))
    assert rtlo.findings[0].severity is Severity.HIGH
    unaccepted = projected(result("defender", status=StageStatus.UNVERIFIED, mode="none",
                                  hits=(evidence("defender", "THREAT", name="Example"),)))
    assert unaccepted.findings[0].severity is Severity.CRITICAL
    assert unaccepted.label == UNKNOWN
    unaccepted.findings.append(Finding("origin", "origin.blocklisted_download", Severity.CRITICAL,
                                       "Blocklisted download URL", 100))
    assert unaccepted.label == "malicious"


def test_scan_result_worst_case_is_small_and_private():
    base = decision(result())
    many = tuple(replace(result(f"engine{i}", hits=(evidence(f"engine{i}", "SIGNAL", name="N" * 512),)),
                         readiness_code="R" * 128) for i in range(64))
    large = replace(base, engine_results=many, reason_codes=tuple("R" * 128 for _ in range(64)),
                    accepted_evidence_ids=tuple("E" * 128 for _ in range(64)),
                    gate_generation="G" * 128)
    summary = project(large, name="sample", path="C:/private", stage_defaults={}).to_dict()["scan_result"]
    encoded = json.dumps(summary).encode("utf-8")
    assert len(encoded) < 64 * 1024
    assert b"C:/private" not in encoded and b"NNNNNN" not in encoded
