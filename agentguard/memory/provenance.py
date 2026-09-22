"""
Layer 9: MemoryProvenanceTracker.

Tracks provenance of every memory entry written by the agent, applies trust
decay across relay hops, quarantines low-trust content, and detects
potential memory-poisoning consistency violations.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import hashlib
import logging
from datetime import datetime
from typing import Any

from agentguard.config import AgentGuardConfig
from agentguard.models import MemoryEntry, TrustReport, TrustTier

logger = logging.getLogger(__name__)

# Trust-tier thresholds used for memory provenance classification.
_TIER_THRESHOLDS: dict[TrustTier, float] = {
    TrustTier.GREEN: 0.65,
    TrustTier.YELLOW: 0.35,
    TrustTier.RED: 0.15,
    TrustTier.QUARANTINE: 0.0,
}


class MemoryProvenanceTracker:
    """
    Gate-keeper for agent memory with full provenance tracking.

    Every value written to memory is annotated with its source URL, trust
    score/tier, content hash, and chain-of-custody.  Low-trust entries are
    automatically quarantined instead of being placed in the main store.

    Parameters
    ----------
    config:
        An :class:`AgentGuardConfig` providing trust thresholds and decay
        parameters.
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        self._store: dict[str, MemoryEntry] = {}
        self._quarantine: dict[str, MemoryEntry] = {}
        self._config = config

    # ------------------------------------------------------------------
    # Core read / write
    # ------------------------------------------------------------------

    def write(
        self,
        key: str,
        value: Any,
        source_url: str | None,
        trust_report: TrustReport,
        chain_of_custody: list[str] | None = None,
    ) -> MemoryEntry | None:
        """
        Write a value to agent memory with full provenance metadata.

        Trust is decayed according to the number of relay hops in
        *chain_of_custody*.  If the effective trust falls below
        ``config.min_trust_to_write_memory`` the write is silently
        rejected (returns ``None``).

        Parameters
        ----------
        key:
            Memory key (unique identifier).
        value:
            Arbitrary value to store.
        source_url:
            URL the value originated from (may be ``None``).
        trust_report:
            The :class:`TrustReport` produced by upstream scanning layers.
        chain_of_custody:
            Ordered list of agent IDs that relayed this value.

        Returns
        -------
        MemoryEntry | None
            The created entry, or ``None`` if the write was blocked.
        """
        content_hash = hashlib.sha256(str(value).encode()).hexdigest()
        source_trust = trust_report.composite_score

        # SECURITY FIX: AG-MP-001 (Adversarial Review 2025)
        # Detect circular chains that could renew trust by looping
        if chain_of_custody:
            seen: set[str] = set()
            for hop in chain_of_custody:
                if hop in seen:
                    logger.warning(
                        "Circular chain detected in memory provenance: %s", hop,
                    )
                    return None  # Block write — circular reference
                seen.add(hop)

        # SECURITY FIX: AG-MP-001 (Adversarial Review 2025)
        # Block writes with excessively long chains to prevent decay evasion
        hop_count = len(chain_of_custody) if chain_of_custody else 0
        if hop_count > self._config.max_trust_hops:
            logger.warning(
                "Chain too long (%d hops, max=%d) — blocking write for key=%r",
                hop_count,
                self._config.max_trust_hops,
                key,
            )
            return None

        # SECURITY FIX: AG-MP-001 (Adversarial Review 2025)
        # Exponential decay instead of linear — each hop halves the trust
        effective_trust = source_trust * (0.5 ** hop_count)

        # SECURITY FIX: AG-MP-001 (Adversarial Review 2025)
        # Hard trust floor — trust cannot go below 0.02 regardless of decay,
        # but writes are still blocked if below min_trust_to_write_memory
        effective_trust = max(effective_trust, 0.02)

        # Block write if below minimum threshold
        if effective_trust < self._config.min_trust_to_write_memory:
            logger.debug(
                "Memory write blocked for key=%r: effective_trust=%.3f "
                "(min=%.3f)",
                key,
                effective_trust,
                self._config.min_trust_to_write_memory,
            )
            return None

        # Classify trust tier using the same thresholds as the scorer
        trust_tier = self._classify_tier(effective_trust)

        entry = MemoryEntry(
            key=key,
            value=value,
            source_url=source_url,
            source_trust_score=effective_trust,
            source_trust_tier=trust_tier,
            chain_of_custody=chain_of_custody or [],
            content_hash=content_hash,
        )

        # Quarantine very low trust entries
        if effective_trust < self._config.quarantine_threshold:
            self._quarantine[key] = entry
            logger.info(
                "Memory entry quarantined: key=%r, trust=%.3f", key, effective_trust,
            )
        else:
            self._store[key] = entry
            logger.debug(
                "Memory entry stored: key=%r, trust=%.3f/%s",
                key,
                effective_trust,
                trust_tier.value,
            )

        return entry

    def read(self, key: str) -> tuple[Any, MemoryEntry] | None:
        """
        Read a value from memory, checking the main store first, then
        quarantine.

        Parameters
        ----------
        key:
            Memory key to look up.

        Returns
        -------
        tuple[Any, MemoryEntry] | None
            ``(value, entry)`` if found, otherwise ``None``.
        """
        entry = self._store.get(key)
        if entry is None:
            entry = self._quarantine.get(key)
        if entry is None:
            return None
        return (entry.value, entry)

    # ------------------------------------------------------------------
    # Context & analysis helpers
    # ------------------------------------------------------------------

    def get_trust_context(self, key: str) -> str:
        """
        Return a human-readable trust context string for a memory key.

        Parameters
        ----------
        key:
            Memory key to look up.

        Returns
        -------
        str
            Formatted context string, or ``"Key not found"``.
        """
        entry = self._store.get(key)
        if entry is None:
            entry = self._quarantine.get(key)
        if entry is None:
            return "Key not found"

        url_display = entry.source_url or "unknown source"
        return (
            f"Value from {url_display} "
            f"(trust: {entry.source_trust_score:.2f}/{entry.source_trust_tier.value}, "
            f"ingested {entry.ingested_at.isoformat()})"
        )

    def detect_consistency_violation(self, key: str, new_value: Any) -> bool:
        """
        Detect a potential memory-poisoning attempt.

        Returns ``True`` when an existing entry is present and the proposed
        *new_value* is significantly different from the current value while
        also having a lower trust assessment (suggesting an overwrite by a
        less-trusted source).

        Parameters
        ----------
        key:
            Memory key to check.
        new_value:
            The proposed new value.

        Returns
        -------
        bool
            ``True`` if a consistency violation is detected.
        """
        existing = self._store.get(key)
        if existing is None:
            return False

        existing_str = str(existing.value)
        new_str = str(new_value)

        # Quick length-based difference check
        if len(existing_str) == 0 and len(new_str) == 0:
            return False

        # Compute a simple ratio: shorter / longer
        min_len = min(len(existing_str), len(new_str))
        max_len = max(len(existing_str), len(new_str))
        if max_len == 0:
            return False

        length_ratio = min_len / max_len
        # If the values are very different in length (ratio < 0.5),
        # or are completely different strings, flag it.
        is_significantly_different = (length_ratio < 0.5) or (existing_str != new_str)

        # For a "significant difference" we also want the length ratio to be
        # meaningfully off or the strings to actually differ in a notable way.
        # A simple heuristic: if they differ at all AND the ratio is low.
        if length_ratio < 0.5:
            is_significantly_different = True
        else:
            # Even at similar lengths, flag if completely different content
            # (no common prefix/suffix overlap)
            common_chars = sum(
                1 for a, b in zip(existing_str, new_str) if a == b
            )
            similarity = common_chars / max_len
            is_significantly_different = similarity < 0.5

        if not is_significantly_different:
            return False

        # New value would need to have lower trust to be considered poisoning
        # Since we don't have a trust_report for new_value here, we check if
        # the existing entry's trust is above a threshold (GREEN/YELLOW) to
        # consider it "trusted enough to protect".
        # We return True if the existing entry is above quarantine level,
        # meaning a new untrusted overwrite would be suspicious.
        protected = existing.source_trust_score >= _TIER_THRESHOLDS[TrustTier.YELLOW]

        if not protected:
            return False

        logger.warning(
            "Consistency violation detected for key=%r: existing value trust=%.3f, "
            "new value appears significantly different",
            key,
            existing.source_trust_score,
        )
        return True

    # ------------------------------------------------------------------
    # Export & management
    # ------------------------------------------------------------------

    def export_provenance_map(self) -> dict:
        """
        Export the full provenance map as a JSON-serializable dict.

        Returns
        -------
        dict
            ``{"memory": {...}, "quarantine": {...}}``
        """
        memory_entries = {
            k: self._entry_to_dict(v) for k, v in self._store.items()
        }
        quarantine_entries = {
            k: self._entry_to_dict(v) for k, v in self._quarantine.items()
        }
        return {"memory": memory_entries, "quarantine": quarantine_entries}

    def quarantine_summary(self) -> list[dict]:
        """
        Return a summary list of all quarantined entries.

        Returns
        -------
        list[dict]
            Each dict contains ``key``, ``source_url``, ``trust_score``,
            and ``reason``.
        """
        summary: list[dict] = []
        for key, entry in self._quarantine.items():
            reason = (
                f"Trust score {entry.source_trust_score:.3f} below quarantine "
                f"threshold {self._config.quarantine_threshold:.3f}"
            )
            summary.append({
                "key": key,
                "source_url": entry.source_url,
                "trust_score": entry.source_trust_score,
                "reason": reason,
            })
        return summary

    def clear(self, trust_tier_min: TrustTier | None = None) -> None:
        """
        Clear memory entries.

        Parameters
        ----------
        trust_tier_min:
            If provided, only clear entries whose effective trust is
            **greater than or equal to** the threshold for this tier.
            If ``None``, clear all entries from both store and quarantine.
        """
        if trust_tier_min is None:
            self._store.clear()
            self._quarantine.clear()
            return

        threshold = _TIER_THRESHOLDS[trust_tier_min]

        # Clear from main store
        keys_to_remove = [
            k for k, v in self._store.items()
            if v.source_trust_score >= threshold
        ]
        for k in keys_to_remove:
            del self._store[k]

        # Clear from quarantine
        q_keys_to_remove = [
            k for k, v in self._quarantine.items()
            if v.source_trust_score >= threshold
        ]
        for k in q_keys_to_remove:
            del self._quarantine[k]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _classify_tier(self, effective_trust: float) -> TrustTier:
        """Map an effective trust score to a :class:`TrustTier`."""
        if effective_trust >= 0.65:
            return TrustTier.GREEN
        if effective_trust >= 0.35:
            return TrustTier.YELLOW
        if effective_trust >= 0.15:
            return TrustTier.RED
        return TrustTier.QUARANTINE

    @staticmethod
    def _entry_to_dict(entry: MemoryEntry) -> dict:
        """Convert a :class:`MemoryEntry` to a JSON-serializable dict."""
        return {
            "key": entry.key,
            "value": entry.value,
            "source_url": entry.source_url,
            "source_trust_score": entry.source_trust_score,
            "source_trust_tier": entry.source_trust_tier.value,
            "ingested_at": entry.ingested_at.isoformat(),
            "chain_of_custody": entry.chain_of_custody,
            "content_hash": entry.content_hash,
        }
