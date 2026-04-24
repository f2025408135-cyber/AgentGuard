"""
Layer 10: AgentTrustValidator.

Provides HMAC-based message signing and verification for inter-agent
communication, along with cascade trust computation across multi-hop
message chains.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import hashlib
import hmac
import json
import logging
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timedelta

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

        # SECURITY FIX: AG-CFG-001 (Adversarial Review 2025)
        # Auto-generate a secure HMAC secret if none is configured.
        # This prevents the "CHANGE_ME_IN_PRODUCTION" anti-pattern where
        # a known-default secret is used in production.
        if not self._config.hmac_secret or self._config.hmac_secret == "CHANGE_ME_IN_PRODUCTION":
            import secrets
            self._hmac_secret = secrets.token_hex(32)
            logger.warning(
                "AG-CFG-001: Using auto-generated HMAC secret. "
                "Set AGENTGUARD_HMAC_SECRET env var for production persistence."
            )
        else:
            self._hmac_secret = self._config.hmac_secret

        # SECURITY FIX: AG-AT-001 (Adversarial Review 2025)
        # LRU nonce cache to detect HMAC signature replay attacks.
        # OrderedDict preserves insertion order for efficient eviction.
        self._seen_nonces: OrderedDict[str, float] = OrderedDict()
        self._max_nonce_cache: int = 10000

    # ------------------------------------------------------------------
    # Internal HMAC computation
    # ------------------------------------------------------------------

    def _compute_signature(self, message: AgentMessage) -> str:
        """
        Compute the HMAC-SHA256 signature for an agent message.

        The payload is a deterministic JSON serialization of the core
        message fields (sorted keys, no whitespace).  If the message
        carries a nonce it is included in the payload so that replayed
        signatures with different nonces are rejected.

        Parameters
        ----------
        message:
            The :class:`AgentMessage` to sign.

        Returns
        -------
        str
            Hexadecimal HMAC digest.
        """
        payload_fields: dict = {
            "sender_id": message.sender_id,
            "recipient_id": message.recipient_id,
            "content": str(message.content),
            "timestamp": message.timestamp.isoformat(),
        }
        # SECURITY FIX: AG-AT-001 (Adversarial Review 2025)
        # Include nonce in HMAC payload when present
        if message.nonce is not None:
            payload_fields["nonce"] = message.nonce

        payload = json.dumps(payload_fields, sort_keys=True)
        return hmac.new(
            self._hmac_secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

    # ------------------------------------------------------------------
    # Nonce replay detection
    # ------------------------------------------------------------------

    def _is_nonce_seen(self, nonce: str) -> bool:
        """
        Check whether *nonce* has already been consumed.

        On first encounter the nonce is recorded with the current
        timestamp and the method returns ``False``.  If the nonce is
        already present the method returns ``True`` (replay detected).

        The internal cache is bounded to ``_max_nonce_cache`` entries.
        Oldest entries are evicted first (FIFO / LRU-style).

        Parameters
        ----------
        nonce:
            UUID nonce string to check.

        Returns
        -------
        bool
            ``True`` if the nonce has been seen before (replay).
        """
        if nonce in self._seen_nonces:
            return True
        self._seen_nonces[nonce] = time.time()
        # Evict oldest entries if cache is full
        while len(self._seen_nonces) > self._max_nonce_cache:
            self._seen_nonces.popitem(last=False)
        return False

    # ------------------------------------------------------------------
    # Sign & verify
    # ------------------------------------------------------------------

    def sign_message(self, message: AgentMessage) -> AgentMessage:
        """
        Produce a signed copy of an agent message.

        A UUIDv4 nonce is generated and embedded in the HMAC payload so
        that every signed message is cryptographically unique, preventing
        replay attacks.  The message also carries an ``expires_at``
        timestamp (5 minutes from signing).

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
        # SECURITY FIX: AG-AT-001 (Adversarial Review 2025)
        # Generate a unique nonce and expiry to prevent replay attacks
        nonce = str(uuid.uuid4())
        expiry_seconds = 300  # 5 minutes

        # Build a temporary message with the nonce so _compute_signature
        # can include it in the HMAC payload.
        message_with_nonce = message.model_copy(update={"nonce": nonce})
        signature = self._compute_signature(message_with_nonce)

        signed = message.model_copy(
            update={
                "signature": signature,
                "trust_score": 1.0,
                "verified": False,
                "nonce": nonce,
                "expires_at": message.timestamp + timedelta(seconds=expiry_seconds),
            }
        )

        logger.debug(
            "Signed message from %s to %s (nonce=%s)",
            message.sender_id,
            message.recipient_id,
            nonce,
        )
        return signed

    def verify_message(self, message: AgentMessage) -> tuple[bool, str]:
        """
        Verify the HMAC signature of an agent message.

        If the message carries no signature and ``config.require_signatures``
        is ``False``, the verification is considered a pass (with a note).

        **Replay detection**: messages that carry a nonce are checked
        against the internal nonce cache.  If the nonce has already been
        seen the verification fails immediately.

        **Expiry check**: messages that carry an ``expires_at`` timestamp
        are rejected if the current time exceeds it.

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

        # SECURITY FIX: AG-AT-001 (Adversarial Review 2025)
        # Check expiry first (cheapest check, no cache lookup needed)
        if message.expires_at is not None:
            if datetime.utcnow() > message.expires_at:
                logger.warning(
                    "Expired message from %s to %s (expires_at=%s)",
                    message.sender_id,
                    message.recipient_id,
                    message.expires_at.isoformat(),
                )
                return (False, "Message expired")

        # SECURITY FIX: AG-AT-001 (Adversarial Review 2025)
        # Check nonce hasn't been seen (replay detection)
        if message.nonce is not None:
            if self._is_nonce_seen(message.nonce):
                logger.warning(
                    "Replay detected: nonce %s from %s already used",
                    message.nonce,
                    message.sender_id,
                )
                return (False, "Replay detected: nonce already used")

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
