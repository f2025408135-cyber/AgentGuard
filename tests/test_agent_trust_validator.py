"""Tests for Layer 10: AgentTrustValidator."""

import pytest
from agentguard.models import AgentMessage


def _make_message(sender="agent_a", recipient="agent_b", content="hello"):
    return AgentMessage(
        sender_id=sender,
        recipient_id=recipient,
        content=content,
    )


class TestSignAndVerify:
    """Test HMAC message signing and verification."""

    def test_sign_and_verify(self, agent_validator):
        msg = _make_message(content="test payload")
        signed = agent_validator.sign_message(msg)

        assert signed.signature is not None
        assert len(signed.signature) > 0
        assert signed.trust_score == 1.0
        assert signed.verified is False

        is_valid, reason = agent_validator.verify_message(signed)
        assert is_valid is True
        assert "valid" in reason.lower()

    def test_different_secret_fails(self, config):
        from agentguard.agents.trust_validator import AgentTrustValidator
        signer = AgentTrustValidator(config)
        verifier = AgentTrustValidator(
            type('obj', (object,), {
                'hmac_secret': 'different_secret',
                'require_signatures': False,
                'max_trust_hops': 5,
            })()
        )

        msg = _make_message(content="test payload")
        signed = signer.sign_message(msg)
        is_valid, reason = verifier.verify_message(signed)
        assert is_valid is False


class TestTamperedMessage:
    """Test that tampered messages fail verification."""

    def test_verify_tampered_message(self, agent_validator):
        msg = _make_message(content="original content")
        signed = agent_validator.sign_message(msg)

        # Tamper with the content after signing
        tampered = signed.model_copy(update={"content": "tampered content"})
        is_valid, reason = agent_validator.verify_message(tampered)
        assert is_valid is False
        assert "failed" in reason.lower()

    def test_verify_tampered_sender(self, agent_validator):
        msg = _make_message(sender="agent_a", content="hello")
        signed = agent_validator.sign_message(msg)

        tampered = signed.model_copy(update={"sender_id": "impostor"})
        is_valid, reason = agent_validator.verify_message(tampered)
        assert is_valid is False


class TestUnsignedMessage:
    """Test handling of unsigned messages."""

    def test_unsigned_message_no_require(self, agent_validator):
        """When require_signatures=False, unsigned messages are accepted."""
        assert agent_validator._config.require_signatures is False
        msg = _make_message(content="unsigned message")
        is_valid, reason = agent_validator.verify_message(msg)
        assert is_valid is True
        assert "not required" in reason.lower()

    def test_unsigned_message_required(self, config):
        """When require_signatures=True, unsigned messages are rejected."""
        config.require_signatures = True
        from agentguard.agents.trust_validator import AgentTrustValidator
        validator = AgentTrustValidator(config)

        msg = _make_message(content="unsigned message")
        is_valid, reason = validator.verify_message(msg)
        assert is_valid is False
        assert "no signature" in reason.lower()


class TestCascadeTrust:
    """Test cascade trust computation across multi-hop chains."""

    def test_cascade_trust_degradation(self, agent_validator):
        """Chain with unsigned hops → reduced trust."""
        msg1 = _make_message(sender="agent_a", recipient="agent_b", content="original")
        msg2 = _make_message(sender="agent_b", recipient="agent_c", content="relayed")
        msg3 = _make_message(sender="agent_c", recipient="agent_d", content="relayed again")

        # All messages are unsigned
        trust = agent_validator.compute_cascade_trust([msg1, msg2, msg3])
        # Each unsigned hop: -0.2. 3 hops: -0.6
        # Each unverified hop: -(0.1 * hop_index): -0.1, -0.2, -0.3 = -0.6
        # Total: 1.0 - 0.6 - 0.6 = -0.2 → clamped to 0.0
        assert trust < 1.0

    def test_cascade_signed_verified_full_trust(self, agent_validator):
        """Fully signed and verified chain → high trust."""
        msg1 = _make_message(sender="agent_a", recipient="agent_b", content="data")
        msg2 = _make_message(sender="agent_b", recipient="agent_c", content="data")
        msg3 = _make_message(sender="agent_c", recipient="agent_d", content="data")

        # Sign all messages
        msg1 = agent_validator.sign_message(msg1)
        msg2 = agent_validator.sign_message(msg2)
        msg3 = agent_validator.sign_message(msg3)

        # verify_message only returns (bool, str) — it doesn't mutate the message.
        # Manually mark as verified for the cascade computation.
        msg1 = msg1.model_copy(update={"verified": True})
        msg2 = msg2.model_copy(update={"verified": True})
        msg3 = msg3.model_copy(update={"verified": True})

        trust = agent_validator.compute_cascade_trust([msg1, msg2, msg3])
        assert trust == 1.0

    def test_cascade_exceeds_max_hops(self, config):
        """Chain longer than max_trust_hops → 0.0 trust."""
        config.max_trust_hops = 3
        from agentguard.agents.trust_validator import AgentTrustValidator
        validator = AgentTrustValidator(config)

        chain = [
            _make_message(sender=f"agent_{i}", recipient=f"agent_{i+1}")
            for i in range(5)
        ]
        trust = validator.compute_cascade_trust(chain)
        assert trust == 0.0
