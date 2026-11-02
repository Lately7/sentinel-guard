from sentinel.service import burst


def op(at, path, kind, *, canary=False, confirmed=True, directory="a"):
    return burst.Operation(at, 123, 456, path, directory, kind, True, canary, confirmed, True)


def test_canary_requires_corrob_and_only_alerts():
    incident = burst.Incident()
    incident.enable()
    assert not incident.observe(op(0, "a/c.txt", "write", canary=True)).alert
    decision = incident.observe(op(1, "b/d.txt", "replace", directory="b"))
    assert decision.alert and decision.state == burst.State.VERIFIED
    assert decision.reason == "corroborated_canary"


def test_general_burst_two_directories_and_read_before_write():
    incident = burst.Incident()
    incident.enable()
    for i in range(8):
        path = f"file-{i}.txt"
        directory = "a" if i < 4 else "b"
        incident.observe(op(i, path, "read", directory=directory))
        decision = incident.observe(op(i + 0.1, path, "write", directory=directory))
    assert decision.alert and decision.reason == "document_burst"


def test_gap_requires_explicit_recovery_and_keeps_counters():
    incident = burst.Incident()
    incident.enable()
    assert incident.observe(op(1, "a", "write"), loss=True).state == burst.State.GAP
    assert not incident.observe(op(2, "b", "write")).alert
    assert not incident.close_gap(3, resubscribed=True, canaries_fresh=False, debt_reconciled=True)
    assert incident.close_gap(4, resubscribed=True, canaries_fresh=True, debt_reconciled=True)
    assert incident.state == burst.State.OBSERVE
    assert incident.counters.gaps == 1


def test_unattributed_and_bounds_open_gap():
    incident = burst.Incident()
    incident.enable()
    bad = burst.Operation(0, 0, 0, "x", "a", "write")
    assert incident.observe(bad).state == burst.State.GAP
    incident.close_gap(1, resubscribed=True, canaries_fresh=True, debt_reconciled=True)
    assert incident.observe(op(2, "x" * (burst.MAX_PATH + 1), "write")).state == burst.State.GAP
    assert incident.counters.truncated == 1


def test_malformed_operation_abstains_without_exception():
    incident = burst.Incident()
    incident.enable()
    malformed = burst.Operation(float("nan"), 123, 456, "x", "a", "write", attributed=True)
    assert incident.observe(malformed).state == burst.State.GAP
    assert incident.counters.parse_failures == 1
