"""Tests for the Routing Engine — destination selection with fail-safe fallback."""
from tsm.fabric.policy_dsl import PolicyOutcome
from tsm.fabric.routing import Destination, RoutingEngine


def test_allow_routes_remote_by_default():
    d = RoutingEngine().route(verdict="allow")
    assert d.destination is Destination.REMOTE
    assert d.degraded is False


def test_block_routes_blocked():
    d = RoutingEngine().route(verdict="block")
    assert d.destination is Destination.BLOCKED


def test_escalate_routes_human():
    d = RoutingEngine().route(verdict="escalate")
    assert d.destination is Destination.HUMAN


def test_quarantine_routes_local():
    d = RoutingEngine().route(verdict="quarantine")
    assert d.destination is Destination.LOCAL


def test_policy_route_target_honoured():
    outcome = PolicyOutcome(action="route", target="local", matched_rule="r", reason="")
    d = RoutingEngine().route(verdict="allow", policy_outcome=outcome)
    assert d.destination is Destination.LOCAL


def test_remote_unavailable_falls_back_to_local():
    eng = RoutingEngine(available={Destination.LOCAL, Destination.HUMAN})
    d = eng.route(verdict="allow")  # wants REMOTE, unavailable
    assert d.destination is Destination.LOCAL
    assert d.degraded is True


def test_local_never_falls_back_to_remote():
    # Sensitive routing (quarantine→local). If local is down, must NOT go remote.
    eng = RoutingEngine(available={Destination.REMOTE})  # only cloud is up
    d = eng.route(verdict="quarantine")
    assert d.destination is not Destination.REMOTE
    assert d.destination in (Destination.QUARANTINE,)  # human down too → quarantine
    assert d.degraded is True


def test_nothing_available_fails_safe_to_quarantine():
    eng = RoutingEngine(available=set())  # everything down
    d = eng.route(verdict="allow")
    assert d.destination is Destination.QUARANTINE
    assert d.degraded is True


def test_human_unavailable_escalation_quarantines():
    eng = RoutingEngine(available={Destination.REMOTE, Destination.LOCAL})  # no human
    d = eng.route(verdict="escalate")
    assert d.destination is Destination.QUARANTINE  # never auto-forwarded
