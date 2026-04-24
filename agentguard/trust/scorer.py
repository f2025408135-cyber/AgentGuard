"""
Layer 6: TrustScorer.

Aggregates detection signals from all upstream layers, computes a
composite trust score, classifies the content into a :class:`TrustTier`,
and produces a human-readable :class:`TrustReport`.

Scoring algorithm
-----------------
1.  Start with ``base_score = 1.0``.
2.  For every :class:`DetectionSignal` subtract
    ``signal.confidence * weight(signal.detector)``.
3.  If asymmetry was detected, subtract an additional
    ``asymmetry_score * weight("asymmetry")``.
4.  Clamp to ``[0.0, 1.0]``.
5.  **Multi-signal amplification**: when 3+ signals come from *different*
    trap classes, the total accumulated penalty is scaled by ``1.3×``.
6.  Map the resulting score to a tier.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import json
from datetime import datetime
from typing import Optional

from agentguard.config import AgentGuardConfig
from agentguard.models import DetectionSignal, TrustReport, TrustTier

# Tier → recommended action
_TIER_ACTIONS: dict[TrustTier, str] = {
    TrustTier.GREEN: "ALLOW",
    TrustTier.YELLOW: "ALLOW_WITH_WARNING",
    TrustTier.RED: "BLOCK",
    TrustTier.QUARANTINE: "QUARANTINE",
}


class TrustScorer:
    """
    Aggregates detection signals into a composite trust score and
    produces a :class:`TrustReport`.

    Parameters
    ----------
    config:
        An :class:`AgentGuardConfig` instance providing scorer weights and
        threshold values.
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Core scoring
    # ------------------------------------------------------------------

    def score(
        self,
        signals: list[DetectionSignal],
        asymmetry_detected: bool,
        asymmetry_score: float,
    ) -> tuple[float, TrustTier]:
        """
        Compute composite trust score and tier from collected signals.

        Parameters
        ----------
        signals:
            All :class:`DetectionSignal` instances from upstream layers.
        asymmetry_detected:
            Whether the DualFetcher detected content asymmetry.
        asymmetry_score:
            Magnitude of the asymmetry difference (0.0 – 1.0).

        Returns
        -------
        tuple[float, TrustTier]
            ``(composite_score, trust_tier)``
        """
        base_score = 1.0
        total_penalty = 0.0
        trap_classes_seen: set[str] = set()

        # --- 2. Accumulate per-signal penalties ----------------------------
        for signal in signals:
            weight = self._config.scorer_weights.get(signal.detector, 0.1)
            penalty = signal.confidence * weight
            total_penalty += penalty
            trap_classes_seen.add(signal.trap_class.value)

        # --- 3. Asymmetry penalty -----------------------------------------
        if asymmetry_detected:
            asymmetry_weight = self._config.scorer_weights.get("asymmetry", 0.20)
            total_penalty += asymmetry_score * asymmetry_weight

        # --- 5. Multi-signal amplification --------------------------------
        if len(trap_classes_seen) >= 3:
            total_penalty *= 1.3

        # --- 4. Compute and clamp score -----------------------------------
        composite_score = base_score - total_penalty
        composite_score = max(0.0, min(1.0, composite_score))

        # --- 6. Determine tier --------------------------------------------
        trust_tier = self._classify_tier(composite_score)

        return composite_score, trust_tier

    # ------------------------------------------------------------------
    # Report building
    # ------------------------------------------------------------------

    def build_report(
        self,
        signals: list[DetectionSignal],
        asymmetry_detected: bool,
        asymmetry_score: float,
        url: Optional[str] = None,
        original_content: Optional[str] = None,
        sanitized_content: Optional[str] = None,
        sanitized_text: Optional[str] = None,
    ) -> TrustReport:
        """
        Build a full :class:`TrustReport` from the scan results.

        Parameters
        ----------
        signals:
            Detection signals from upstream layers.
        asymmetry_detected:
            Whether content asymmetry was detected.
        asymmetry_score:
            Magnitude of asymmetry (0.0 – 1.0).
        url:
            The URL that was scanned (if applicable).
        original_content:
            The original (raw) content before sanitization.
        sanitized_content:
            The content after sanitization (for HTML content).
        sanitized_text:
            The sanitized text (for plain-text scans where
            HTML sanitization is not applicable).  When provided and
            ``sanitized_content`` is ``None``, this value is used as
            the ``sanitized_content`` in the report.

        Returns
        -------
        TrustReport
        """
        composite_score, trust_tier = self.score(
            signals, asymmetry_detected, asymmetry_score,
        )
        action = _TIER_ACTIONS[trust_tier]

        # Build an asymmetry diff summary when relevant
        asymmetry_diff_summary: str | None = None
        if asymmetry_detected:
            pct = round(asymmetry_score * 100, 1)
            asymmetry_diff_summary = (
                f"Content asymmetry detected: {pct}% difference between "
                f"human-facing and bot-facing versions."
            )

        # When sanitized_text is provided (plain-text scans), use it
        # as sanitized_content if no HTML-level sanitization was done.
        effective_sanitized = sanitized_content
        if effective_sanitized is None and sanitized_text is not None:
            effective_sanitized = sanitized_text

        return TrustReport(
            url=url,
            trust_tier=trust_tier,
            composite_score=composite_score,
            signals=signals,
            asymmetry_detected=asymmetry_detected,
            asymmetry_diff_summary=asymmetry_diff_summary,
            sanitized_content=effective_sanitized,
            original_content=original_content,
            action_taken=action,
        )

    # ------------------------------------------------------------------
    # Human-readable summary
    # ------------------------------------------------------------------

    def summarize(self, trust_report: TrustReport) -> str:
        """
        Produce a multi-line human-readable summary of a trust report.

        Parameters
        ----------
        trust_report:
            A :class:`TrustReport` instance.

        Returns
        -------
        str
        """
        lines: list[str] = []

        lines.append("=" * 60)
        lines.append("  AgentGuard Trust Report")
        lines.append("=" * 60)

        if trust_report.url:
            lines.append(f"  URL:             {trust_report.url}")
        lines.append(f"  Timestamp:       {trust_report.timestamp.isoformat()}")
        lines.append(f"  Trust Tier:      {trust_report.trust_tier.value}")
        lines.append(f"  Composite Score: {trust_report.composite_score:.4f}")
        lines.append(f"  Action Taken:    {trust_report.action_taken}")

        lines.append("")
        lines.append(f"  Total Signals:   {len(trust_report.signals)}")

        if trust_report.asymmetry_detected:
            lines.append(
                f"  Asymmetry:       DETECTED "
                f"(score={trust_report.asymmetry_diff_summary})"
            )
        else:
            lines.append("  Asymmetry:       not detected")

        # Top signals by confidence
        if trust_report.signals:
            sorted_signals = sorted(
                trust_report.signals, key=lambda s: s.confidence, reverse=True,
            )
            top_n = min(5, len(sorted_signals))
            lines.append("")
            lines.append(f"  Top {top_n} Signal(s) by Confidence:")
            lines.append("-" * 60)
            for i, sig in enumerate(sorted_signals[:top_n], 1):
                lines.append(f"  {i}. [{sig.detector}] {sig.signal_name}")
                lines.append(f"     Confidence: {sig.confidence:.2f}  "
                             f"Trap: {sig.trap_class.value}")
                lines.append(f"     Evidence:   {sig.evidence[:150]}")
                if i < top_n:
                    lines.append("")

        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # JSON-serializable dict
    # ------------------------------------------------------------------

    def to_dict(self, trust_report: TrustReport) -> dict:
        """
        Convert a :class:`TrustReport` to a JSON-serializable ``dict``.

        Handles :class:`datetime` and enum serialization.

        Parameters
        ----------
        trust_report:
            A :class:`TrustReport` instance.

        Returns
        -------
        dict
        """
        signals_list = []
        for sig in trust_report.signals:
            sig_dict = {
                "trap_class": sig.trap_class.value,
                "signal_name": sig.signal_name,
                "confidence": sig.confidence,
                "evidence": sig.evidence,
                "detector": sig.detector,
            }
            if sig.raw_payload is not None:
                sig_dict["raw_payload"] = sig.raw_payload
            signals_list.append(sig_dict)

        result = {
            "url": trust_report.url,
            "timestamp": (
                trust_report.timestamp.isoformat()
                if trust_report.timestamp
                else None
            ),
            "trust_tier": trust_report.trust_tier.value,
            "composite_score": trust_report.composite_score,
            "signals": signals_list,
            "asymmetry_detected": trust_report.asymmetry_detected,
            "asymmetry_diff_summary": trust_report.asymmetry_diff_summary,
            "sanitized_content": trust_report.sanitized_content,
            "original_content": trust_report.original_content,
            "action_taken": trust_report.action_taken,
            "metadata": trust_report.metadata,
        }

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _classify_tier(self, score: float) -> TrustTier:
        """Map a composite score to a :class:`TrustTier`."""
        if score >= self._config.yellow_threshold:
            return TrustTier.GREEN
        if score >= self._config.red_threshold:
            return TrustTier.YELLOW
        if score >= 0.15:
            return TrustTier.RED
        return TrustTier.QUARANTINE
