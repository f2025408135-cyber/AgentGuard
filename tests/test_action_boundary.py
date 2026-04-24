"""Tests for Layer 7: ActionBoundaryEnforcer."""

import pytest
from agentguard.models import TrustTier, ActionRequest, TrustReport


def _make_action(action_type, trust_tier=None, composite_score=0.5):
    report = None
    if trust_tier is not None:
        report = TrustReport(
            trust_tier=trust_tier,
            composite_score=composite_score,
        )
    return ActionRequest(
        action_type=action_type,
        trust_report=report,
    )


class TestAlwaysBlocked:
    """Test that always-blocked actions are rejected."""

    def test_blocks_spawn_agent(self, action_enforcer):
        action = _make_action("spawn_agent")
        allowed, reason = action_enforcer.validate(action)
        assert allowed is False
        assert "always blocked" in reason.lower() or "blocked" in reason.lower()

    def test_blocks_execute_code(self, action_enforcer):
        action = _make_action("execute_code")
        allowed, reason = action_enforcer.validate(action)
        assert allowed is False

    def test_blocks_send_email(self, action_enforcer):
        action = _make_action("send_email")
        allowed, reason = action_enforcer.validate(action)
        assert allowed is False

    def test_blocks_modify_system_prompt(self, action_enforcer):
        action = _make_action("modify_system_prompt")
        allowed, reason = action_enforcer.validate(action)
        assert allowed is False


class TestGreenTier:
    """Test actions allowed at GREEN trust tier."""

    def test_allows_standard_actions_green(self, action_enforcer):
        action = _make_action("fetch_url", trust_tier=TrustTier.GREEN, composite_score=0.9)
        allowed, reason = action_enforcer.validate(action)
        assert allowed is True

    def test_allows_write_file_green(self, action_enforcer):
        action = _make_action("write_file", trust_tier=TrustTier.GREEN, composite_score=0.9)
        allowed, reason = action_enforcer.validate(action)
        assert allowed is True


class TestQuarantineTier:
    """Test that QUARANTINE tier blocks all actions."""

    def test_quarantine_blocks_all(self, action_enforcer):
        for action_type in ["fetch_url", "read_file", "search", "summarize"]:
            action = _make_action(action_type, trust_tier=TrustTier.QUARANTINE, composite_score=0.05)
            allowed, reason = action_enforcer.validate(action)
            assert allowed is False, f"Action {action_type} should be blocked at QUARANTINE"


class TestRedTier:
    """Test that RED tier restricts to read-only actions."""

    def test_red_allows_read_file(self, action_enforcer):
        action = _make_action("read_file", trust_tier=TrustTier.RED, composite_score=0.2)
        allowed, reason = action_enforcer.validate(action)
        assert allowed is True

    def test_red_allows_summarize(self, action_enforcer):
        action = _make_action("summarize", trust_tier=TrustTier.RED, composite_score=0.2)
        allowed, reason = action_enforcer.validate(action)
        assert allowed is True

    def test_red_restricts_fetch_url(self, action_enforcer):
        action = _make_action("fetch_url", trust_tier=TrustTier.RED, composite_score=0.2)
        allowed, reason = action_enforcer.validate(action)
        assert allowed is False

    def test_red_restricts_write_file(self, action_enforcer):
        action = _make_action("write_file", trust_tier=TrustTier.RED, composite_score=0.2)
        allowed, reason = action_enforcer.validate(action)
        assert allowed is False


class TestYellowTier:
    """Test YELLOW tier action restrictions."""

    def test_yellow_allows_fetch_url(self, action_enforcer):
        action = _make_action("fetch_url", trust_tier=TrustTier.YELLOW, composite_score=0.5)
        allowed, reason = action_enforcer.validate(action)
        assert allowed is True

    def test_yellow_blocks_execute_code(self, action_enforcer):
        action = _make_action("execute_code", trust_tier=TrustTier.YELLOW, composite_score=0.5)
        allowed, reason = action_enforcer.validate(action)
        assert allowed is False

    def test_yellow_blocks_spawn_agent(self, action_enforcer):
        action = _make_action("spawn_agent", trust_tier=TrustTier.YELLOW, composite_score=0.5)
        allowed, reason = action_enforcer.validate(action)
        assert allowed is False


class TestUnknownAction:
    """Test that unknown action types are blocked."""

    def test_unknown_action_blocked(self, action_enforcer):
        action = _make_action("launch_missiles")
        allowed, reason = action_enforcer.validate(action)
        assert allowed is False
        assert "unknown" in reason.lower()


class TestExplain:
    """Test the explain method."""

    def test_explain_output(self, action_enforcer):
        action = _make_action("spawn_agent")
        explanation = action_enforcer.explain(action)
        assert isinstance(explanation, str)
        assert len(explanation) > 0
        assert "spawn_agent" in explanation

    def test_explain_allowed(self, action_enforcer):
        action = _make_action("fetch_url", trust_tier=TrustTier.GREEN, composite_score=0.9)
        explanation = action_enforcer.explain(action)
        assert "ALLOWED" in explanation
