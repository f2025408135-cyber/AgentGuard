"""
Layer 7: Action Boundary Enforcer.

Enforces trust-tier-aware action policies.  Actions are classified by the
agent's *action_type* string and compared against the configured allow-list
and block-list, then further gated by the trust tier of the associated
content (if a :class:`TrustReport` is present).

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agentguard.config import AgentGuardConfig
from agentguard.models import ActionRequest, TrustTier

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Action types that count as "write" operations for RED-tier gating.
_WRITE_OPS: set[str] = {"write_file", "modify_system_prompt", "change_permissions"}

# Action types that count as "network" calls for RED-tier gating.
_NETWORK_OPS: set[str] = {"fetch_url", "send_email", "search"}

# Action types that count as "agent spawning" for RED-tier gating.
_SPAWN_OPS: set[str] = {"spawn_agent", "execute_code"}

# Actions blocked for YELLOW tier (on top of always_blocked_actions).
_YELLOW_BLOCKED: set[str] = {"send_email", "spawn_agent", "execute_code"}

# Actions explicitly allowed for RED tier.
_RED_ALLOWED: set[str] = {"read_file", "summarize"}


class ActionBoundaryEnforcer:
    """Trust-tier-aware action boundary enforcer (Layer 7).

    Each incoming :class:`ActionRequest` is validated against:
      1. The *always blocked* list (hard block regardless of trust).
      2. The *allowed action types* whitelist (unknown types are blocked).
      3. Trust-tier-specific policies that progressively restrict dangerous
         actions as the trust tier degrades from GREEN → QUARANTINE.
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        self._config = config
        self._always_blocked: set[str] = set(config.always_blocked_actions)
        self._allowed: set[str] = set(config.allowed_action_types)
        logger.debug(
            "ActionBoundaryEnforcer initialised: %d allowed, %d always-blocked",
            len(self._allowed),
            len(self._always_blocked),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, action: ActionRequest) -> tuple[bool, str]:
        """Validate *action* against boundary rules.

        Returns ``(is_allowed, reason)``.
        """
        action_type = action.action_type

        # Rule 1 — always blocked
        if action_type in self._always_blocked:
            reason = f"Action '{action_type}' is always blocked"
            logger.warning("Action blocked (always-blocked): %s", reason)
            return (False, reason)

        # Rule 2 — unknown action type
        if action_type not in self._allowed:
            reason = f"Unknown action type: '{action_type}'"
            logger.warning("Action blocked (unknown): %s", reason)
            return (False, reason)

        # Rule 3 — trust-tier gating
        if action.trust_report is not None:
            tier = action.trust_report.trust_tier
            allowed, reason = self._check_tier(action_type, tier)
            if not allowed:
                logger.warning(
                    "Action blocked (tier=%s): %s — %s",
                    tier.value,
                    action_type,
                    reason,
                )
                return (False, reason)
            return (True, "Allowed")

        # Rule 4 — no trust report → allow if in whitelist
        return (True, "Allowed")

    def get_allowed_actions(self, trust_tier: TrustTier) -> list[str]:
        """Return the set of action types permitted for *trust_tier*."""
        if trust_tier == TrustTier.GREEN:
            return sorted(self._allowed)
        if trust_tier == TrustTier.YELLOW:
            return sorted(self._allowed - _YELLOW_BLOCKED - self._always_blocked)
        if trust_tier == TrustTier.RED:
            return sorted(_RED_ALLOWED & self._allowed)
        # QUARANTINE — nothing is allowed
        return []

    def explain(self, action: ActionRequest) -> str:
        """Return a human-readable explanation of the enforcement decision.

        Includes the relevant trust tier, action type, and which rule(s)
        apply.
        """
        action_type = action.action_type
        lines: list[str] = []

        # Header
        lines.append(f"Action Boundary Enforcement Report")
        lines.append(f"{'=' * 42}")
        lines.append(f"  Action type : {action_type}")

        # Trust tier
        if action.trust_report is not None:
            tier = action.trust_report.trust_tier
            score = action.trust_report.composite_score
            lines.append(f"  Trust tier  : {tier.value} (score={score:.3f})")
        else:
            lines.append("  Trust tier  : N/A (no trust report)")
            tier = None

        lines.append("")

        # --- Check rules in order and annotate ---
        # Rule 1
        if action_type in self._always_blocked:
            lines.append(f"[BLOCKED] Rule 1 — Always-blocked action.")
            lines.append(f"  '{action_type}' is in the always-blocked list.")
            lines.append(
                f"  Blocked actions: {', '.join(sorted(self._always_blocked))}"
            )
            return "\n".join(lines)

        # Rule 2
        if action_type not in self._allowed:
            lines.append("[BLOCKED] Rule 2 — Unknown action type.")
            lines.append(f"  '{action_type}' is not in the allowed-action list.")
            return "\n".join(lines)

        # Rule 3
        if action.trust_report is not None:
            allowed_for_tier = self.get_allowed_actions(tier)  # type: ignore[arg-type]
            if action_type in allowed_for_tier:
                lines.append(
                    f"[ALLOWED] Rule 3 — Action permitted at {tier.value} tier."
                )
                lines.append(
                    f"  '{action_type}' is in the allowed set for {tier.value}: "
                    f"{', '.join(allowed_for_tier)}"
                )
            else:
                lines.append(
                    f"[BLOCKED] Rule 3 — Action NOT permitted at {tier.value} tier."
                )
                lines.append(f"  '{action_type}' is restricted for {tier.value} content.")
                lines.append(
                    f"  Allowed actions at {tier.value}: "
                    f"{', '.join(allowed_for_tier) if allowed_for_tier else '(none)'}"
                )
            return "\n".join(lines)

        # Rule 4
        lines.append(
            "[ALLOWED] Rule 4 — No trust report attached; "
            "action is in the allowed-action list."
        )
        lines.append(
            f"  Allowed actions: {', '.join(sorted(self._allowed))}"
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_tier(
        self, action_type: str, tier: TrustTier
    ) -> tuple[bool, str]:
        """Apply trust-tier-specific rules.  Returns (allowed, reason)."""

        if tier == TrustTier.QUARANTINE:
            return (
                False,
                "Content is quarantined — all actions blocked",
            )

        if tier == TrustTier.RED:
            if action_type not in _RED_ALLOWED:
                # Provide a specific reason based on what category the
                # blocked action falls into.
                if action_type in _WRITE_OPS:
                    return (False, "Write operations blocked at RED trust tier")
                if action_type in _NETWORK_OPS:
                    return (False, "Network calls blocked at RED trust tier")
                if action_type in _SPAWN_OPS:
                    return (False, "Agent spawning blocked at RED trust tier")
                return (False, "Action blocked at RED trust tier")
            return (True, "Allowed")

        if tier == TrustTier.YELLOW:
            if action_type in _YELLOW_BLOCKED:
                return (
                    False,
                    f"Action '{action_type}' is blocked at YELLOW trust tier",
                )
            return (True, "Allowed")

        # GREEN — everything not already hard-blocked is fine
        return (True, "Allowed")
