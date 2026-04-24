"""
Layer 10: AgentTrustValidator.

Provides HMAC-based message signing and verification for inter-agent
communication, along with cascade trust computation across multi-hop
message chains.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import hmac
import hashlib
import json
import logging

from agentguard.config import AgentGuardConfig
from agentguard.models import AgentMessage
from agentguard.exceptions import TrustValidationError

logger = logging.getLogger(__name__)


class AgentTrustValidator:
    """
    Signs, verifies, and evaluates trust for inter-agent messages.

    Each message is signed with an HMAC-SHA256 derived from a shared
    secret (``config.hmac_secret``).  Trust degrades as messages traverse
    unsigned or unverified hops in a chain.

    Parameters
    ----------
    config:
        An :class:`AgentGuardConfig` providing HMAC secret, signature
        policy, and hop limits.
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Internal HMAC computation
    # ------------------------------------------------------------------

    def _compute_signature(self, message: AgentMessage) -> str:
        """
        Compute the HMAC-SHA256 signature for an agent message.

        The payload is a deterministic JSON serialization of the core
        message fields (sorted keys, no whitespace).

        Parameters
        ----------
        message:
            The :class:`AgentMessage` to sign.

        Returns
        -------
        str
            Hexadecimal HMAC digest.
        """
        payload = json.dumps(
            {
                "sender_id": message.sender_id,
                "recipient_id": message.recipient_id,
                "content": str(message.content),
                "timestamp": message.timestamp.isoformat(),
            },
            sort_keys=True,
        )
        return hmac.new(
            self._config.hmac_secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

    # ------------------------------------------------------------------
    # Sign & verify
    # ------------------------------------------------------------------

    def sign_message(self, message: AgentMessage) -> AgentMessage:
        """
        Produce a signed copy of an agent message.

        The returned copy has its ``signature`` field populated and
        ``trust_score`` set to ``1.0``.  ``verified`` is set to ``False``
        because the signature must be independently verified by the
        recipient.

        Parameters
        ----------
        message:
            The original :class:`AgentMessage`.

        Returns
        -------
        AgentMessage
            A new message instance with the signature attached.
        """
        signature = self._compute_signature(message)

        signed = message.model_copy(
            update={
                "signature": signature,
                "trust_score": 1.0,
                "verified": False,
            }
        )

        logger.debug(
            "Signed message from %s to %s",
            message.sender_id,
            message.recipient_id,
        )
        return signed

    def verify_message(self, message: AgentMessage) -> tuple[bool, str]:
        """
        Verify the HMAC signature of an agent message.

        If the message carries no signature and ``config.require_signatures``
        is ``False``, the verification is considered a pass (with a note).

        Parameters
        ----------
        message:
            The :class:`AgentMessage` to verify.

        Returns
        -------
        tuple[bool, str]
            ``(is_valid, reason)`` — ``is_valid`` is ``True`` when the
            message passes verification.
        """
        if message.signature is None:
            if self._config.require_signatures:
                logger.warning(
                    "Message from %s rejected: no signature and signatures required",
                    message.sender_id,
                )
                return (False, "No signature present and signatures are required")
            else:
                logger.debug(
                    "Message from %s accepted without signature (not required)",
                    message.sender_id,
                )
                return (True, "No signature (signatures not required)")

        # Recompute the expected signature
        expected = self._compute_signature(message)

        if hmac.compare_digest(expected, message.signature):
            logger.debug(
                "Signature verified for message from %s to %s",
                message.sender_id,
                message.recipient_id,
            )
            return (True, "Signature valid")
        else:
            logger.warning(
                "Signature verification FAILED for message from %s to %s",
                message.sender_id,
                message.recipient_id,
            )
            return (False, "Signature verification failed")

    # ------------------------------------------------------------------
    # Cascade trust across multi-hop chains
    # ------------------------------------------------------------------

    def compute_cascade_trust(self, message_chain: list[AgentMessage]) -> float:
        """
        Compute a composite trust score for a multi-hop message chain.

        Trust starts at ``1.0`` and degrades for:
        * Messages without a signature (``-0.2`` per unsigned hop).
        * Messages that have not been verified (``-0.1 × hop_index``).

        If the chain exceeds ``config.max_trust_hops``, trust drops to ``0.0``.

        Parameters
        ----------
        message_chain:
            Ordered list of :class:`AgentMessage` instances representing
            the relay chain (index 0 = origin).

        Returns
        -------
        float
            Cascade trust score in ``[0.0, 1.0]``.
        """
        if len(message_chain) > self._config.max_trust_hops:
            logger.warning(
                "Message chain exceeds max_trust_hops (%d > %d); trust set to 0.0",
                len(message_chain),
                self._config.max_trust_hops,
            )
            return 0.0

        trust = 1.0

        for hop_index, message in enumerate(message_chain):
            # Unsigned hop penalty
            if message.signature is None:
                trust -= 0.2

            # Unverified hop penalty (scales with distance from origin)
            if not message.verified:
                trust -= 0.1 * (hop_index + 1)

        # Clamp to [0.0, 1.0]
        trust = max(0.0, min(1.0, trust))

        logger.debug(
            "Cascade trust for %d-hop chain: %.3f",
            len(message_chain),
            trust,
        )
        return trust
