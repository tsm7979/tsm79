"""
Tests: detector/policy_engine.py
Coverage: builtin rules, custom rules, priority ordering, persistence
"""
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest
import detector.policy_engine as _pe
from detector.policy_engine import PolicyEngine, PolicyRule


@contextmanager
def isolated_engine():
    """Context manager: PolicyEngine with a throwaway policy file."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        f.write("{}")
        tmp = Path(f.name)
    original = _pe._POLICY_PATH
    _pe._POLICY_PATH = tmp
    try:
        yield PolicyEngine(), tmp
    finally:
        _pe._POLICY_PATH = original
        tmp.unlink(missing_ok=True)


# ── Builtin rules ─────────────────────────────────────────────────────────────

def test_jailbreak_blocked():
    with isolated_engine() as (e, _):
        r = e.evaluate(["JAILBREAK"], 100, "critical", None, "gpt-4", {})
        assert r.action == "block"
        assert r.rule_name == "block_jailbreak"

def test_secrets_blocked():
    with isolated_engine() as (e, _):
        for stype in ["GITHUB_TOKEN", "OPENAI_KEY", "ANTHROPIC_KEY", "AWS_KEY", "PRIVATE_KEY"]:
            r = e.evaluate([stype], 98, "critical", None, "gpt-4", {})
            assert r.action == "block", f"Expected block for {stype}"

def test_critical_pii_routed_local():
    with isolated_engine() as (e, _):
        r = e.evaluate(["SSN"], 94, "critical", None, "gpt-4", {})
        assert r.action == "route_local"
        assert r.rule_name == "local_critical_pii"

def test_high_pii_redacted():
    with isolated_engine() as (e, _):
        r = e.evaluate(["CREDIT_CARD"], 92, "high", None, "gpt-4", {})
        assert r.action == "redact"

def test_medium_risk_redacted():
    with isolated_engine() as (e, _):
        r = e.evaluate(["EMAIL"], 40, "medium", None, "gpt-4", {})
        assert r.action == "redact"

def test_clean_allowed():
    with isolated_engine() as (e, _):
        r = e.evaluate([], 0, "none", None, "gpt-4", {})
        assert r.action == "allow"


# ── Priority ordering ─────────────────────────────────────────────────────────

def test_jailbreak_beats_clean():
    with isolated_engine() as (e, _):
        r = e.evaluate(["JAILBREAK"], 0, "none", None, "gpt-4", {})
        assert r.action == "block"

def test_custom_rule_higher_priority_wins():
    with isolated_engine() as (e, _):
        e.add_rule(PolicyRule(
            name="dev_allow_secrets",
            priority=1,
            condition={"any_of": ["GITHUB_TOKEN"], "user_role": "dev-internal"},
            action="allow",
        ))
        r = e.evaluate(["GITHUB_TOKEN"], 98, "critical", "dev-internal", "gpt-4", {})
        assert r.action == "allow"
        assert r.rule_name == "dev_allow_secrets"


# ── Custom rule conditions ────────────────────────────────────────────────────

def test_rule_any_of_match():
    with isolated_engine() as (e, _):
        # priority 5 beats all builtins (lowest priority wins first)
        e.add_rule(PolicyRule("test_any", {"any_of": ["EMAIL", "PHONE"]}, "redact", 5))
        r = e.evaluate(["EMAIL"], 40, "medium", None, "gpt-4", {})
        assert r.rule_name == "test_any"

def test_rule_any_of_no_match():
    with isolated_engine() as (e, _):
        e.add_rule(PolicyRule("test_any", {"any_of": ["PASSPORT"]}, "block", 50))
        r = e.evaluate(["EMAIL"], 40, "medium", None, "gpt-4", {})
        assert r.rule_name != "test_any"

def test_rule_risk_score_gte():
    with isolated_engine() as (e, _):
        e.add_rule(PolicyRule("high_risk", {"risk_score_gte": 75}, "block", 5))
        r = e.evaluate([], 80, "none", None, "gpt-4", {})
        assert r.rule_name == "high_risk"
        assert r.action == "block"

def test_rule_risk_score_lt_no_match():
    with isolated_engine() as (e, _):
        e.add_rule(PolicyRule("high_risk", {"risk_score_gte": 75}, "block", 5))
        r = e.evaluate([], 50, "none", None, "gpt-4", {})
        assert r.rule_name != "high_risk"

def test_rule_user_role_match():
    with isolated_engine() as (e, _):
        e.add_rule(PolicyRule(
            "admin_block", {"contains_pii": True, "user_role": "admin"}, "block", 3
        ))
        r = e.evaluate(["EMAIL"], 40, "medium", "admin", "gpt-4", {})
        assert r.rule_name == "admin_block"
        assert r.action == "block"

def test_rule_user_role_no_match():
    with isolated_engine() as (e, _):
        e.add_rule(PolicyRule(
            "admin_block", {"contains_pii": True, "user_role": "admin"}, "block", 3
        ))
        r = e.evaluate(["EMAIL"], 40, "medium", "developer", "gpt-4", {})
        assert r.rule_name != "admin_block"

def test_rule_model_prefix():
    with isolated_engine() as (e, _):
        e.add_rule(PolicyRule(
            "gpt4_pii_block", {"model_prefix": "gpt-4", "contains_pii": True}, "block", 3
        ))
        r = e.evaluate(["EMAIL"], 40, "medium", None, "gpt-4-turbo", {})
        assert r.rule_name == "gpt4_pii_block"

def test_rule_model_prefix_no_match():
    with isolated_engine() as (e, _):
        e.add_rule(PolicyRule(
            "gpt4_pii_block", {"model_prefix": "gpt-4", "contains_pii": True}, "block", 3
        ))
        r = e.evaluate(["EMAIL"], 40, "medium", None, "gpt-3.5-turbo", {})
        assert r.rule_name != "gpt4_pii_block"


# ── Add / remove / persist ────────────────────────────────────────────────────

def test_add_and_remove_rule():
    with isolated_engine() as (e, _):
        e.add_rule(PolicyRule("my_rule", {"any_of": ["EMAIL"]}, "block", 50))
        assert any(r["name"] == "my_rule" for r in e.rules_as_dict())
        removed = e.remove_rule("my_rule")
        assert removed is True
        assert not any(r["name"] == "my_rule" for r in e.rules_as_dict())

def test_remove_nonexistent_rule():
    with isolated_engine() as (e, _):
        assert e.remove_rule("does_not_exist") is False

def test_rules_persisted_to_disk():
    with isolated_engine() as (e, tmp):
        e.add_rule(PolicyRule("persist_test", {"any_of": ["EMAIL"]}, "block", 50))
        data = json.loads(tmp.read_text())
        assert any(r["name"] == "persist_test" for r in data["rules"])

def test_rules_loaded_on_init():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        json.dump({"rules": [
            {"name": "loaded_rule", "condition": {"any_of": ["SSN"]}, "action": "block", "priority": 5}
        ]}, f)
        tmp = Path(f.name)
    original = _pe._POLICY_PATH
    _pe._POLICY_PATH = tmp
    try:
        e = PolicyEngine()
        assert any(r["name"] == "loaded_rule" for r in e.rules_as_dict())
    finally:
        _pe._POLICY_PATH = original
        tmp.unlink(missing_ok=True)

def test_add_rule_replaces_existing():
    with isolated_engine() as (e, _):
        e.add_rule(PolicyRule("dup", {"any_of": ["EMAIL"]}, "block", 50))
        e.add_rule(PolicyRule("dup", {"any_of": ["EMAIL"]}, "allow", 50))
        matching = [r for r in e.rules_as_dict() if r["name"] == "dup"]
        assert len(matching) == 1
        assert matching[0]["action"] == "allow"


# ── rules_as_dict ─────────────────────────────────────────────────────────────

def test_rules_as_dict_sorted_by_priority():
    with isolated_engine() as (e, _):
        rules = e.rules_as_dict()
        priorities = [r["priority"] for r in rules]
        assert priorities == sorted(priorities)

def test_rules_include_source():
    with isolated_engine() as (e, _):
        for r in e.rules_as_dict():
            assert r["source"] in ("builtin", "custom")

def test_builtin_rules_present():
    with isolated_engine() as (e, _):
        names = {r["name"] for r in e.rules_as_dict()}
        assert "block_jailbreak" in names
        assert "block_secrets" in names
        assert "allow_clean" in names
