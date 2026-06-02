"""Tests for the Recovery Engine — the autonomous threat→...→validation loop."""
from tsm.fabric.recovery import Incident, RecoveryEngine, RecoveryStage


def test_full_recovery_loop_with_defaults():
    inc = RecoveryEngine().handle("ransomware beacon", severity="critical")
    assert inc.resolved is True
    assert inc.escalated is False
    assert inc.stage is RecoveryStage.RESTORED
    assert inc.stages == (
        "detected", "assessed", "isolated", "recovering", "validating", "restored")


def test_low_severity_is_monitored_not_isolated():
    inc = RecoveryEngine().handle("port scan", severity="low")
    assert inc.resolved is True
    assert "isolated" not in inc.stages
    assert inc.stage is RecoveryStage.RESTORED


def test_isolation_failure_escalates():
    eng = RecoveryEngine(isolator=lambda inc: False)
    inc = eng.handle("threat", severity="high")
    assert inc.escalated is True
    assert inc.resolved is False
    assert inc.stage is RecoveryStage.ESCALATED


def test_recovery_failure_escalates():
    eng = RecoveryEngine(recoverer=lambda inc: False)
    inc = eng.handle("threat", severity="high")
    assert inc.escalated is True
    assert "recovering" in inc.stages


def test_validation_failure_escalates():
    # recovery applied but didn't hold -> must escalate, not declare success
    eng = RecoveryEngine(validator=lambda inc: False)
    inc = eng.handle("threat", severity="high")
    assert inc.escalated is True
    assert inc.stage is RecoveryStage.ESCALATED


def test_handler_exception_escalates_not_crashes():
    def boom(inc):
        raise RuntimeError("isolator crashed")

    inc = RecoveryEngine(isolator=boom).handle("threat", severity="critical")
    assert inc.escalated is True  # crash contained, escalated safely


def test_assessor_can_raise_severity():
    # caller said low, assessor upgrades to critical -> full loop runs
    eng = RecoveryEngine(assessor=lambda inc: "critical")
    inc = eng.handle("suspicious", severity="low")
    assert "isolated" in inc.stages
    assert inc.resolved is True


def test_audit_receives_every_transition():
    seen = []
    eng = RecoveryEngine(audit=seen.append)
    eng.handle("threat", severity="critical")
    stages = [e["stage"] for e in seen]
    assert "detected" in stages and "restored" in stages
    assert all("incident" in e for e in seen)


def test_incident_is_serializable():
    import json
    inc = RecoveryEngine().handle("threat", severity="high", subject="host-7")
    assert json.dumps(inc.as_dict())
