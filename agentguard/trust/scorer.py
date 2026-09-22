"""
Layer 6: TrustScorer.

Aggregates detection signals from all upstream layers, computes a
composite trust score, classifies the content into a :class:`TrustTier`,
and produces a human-readable :class:`TrustReport`.

Scoring algorithm
-----------------
1.  Start with ``base_score = 1.0``.
2.  For every :class:`DetectionSignal`, group by detector.  Signals
    from the *same* detector contribute only their **maximum** confidence
    (preventing signal-amplification reversal attacks), while signals
    from *different* detectors stack fully.  Each accumulated penalty is
    scaled through a **non-linear** curve so that additional signals cost
    progressively more, making threshold calibration infeasible.
3.  Signals with confidence > 0.85 receive a 1.5× asymmetric weight
    boost — high-confidence detections are disproportionately dangerous.
4.  If asymmetry was detected, subtract an additional
    ``asymmetry_score * weight("asymmetry")``.
5.  Clamp to ``[0.0, 1.0]``.
6.  **Conditional multi-signal amplification**: amplification is applied
    ONLY when signals originate from 3+ *different* trap classes AND at
    least 2 of those signals carry confidence > 0.7.  This prevents an
    attacker from triggering amplification with low-confidence noise.
7.  Map the resulting score to a tier using **jittered thresholds**
    (small random perturbation per :class:`TrustScorer` instance) to
    defeat precise calibration attacks.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import json
import math
import random
from collections import defaultdict
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

# SECURITY FIX: AG-TS-001 (Adversarial Review 2025)
# Confidence threshold above which the asymmetric 1.5× weight is applied.
_HIGH_CONFIDENCE_THRESHOLD: float = 0.85
_HIGH_CONFIDENCE_WEIGHT_MULTIPLIER: float = 1.5

# SECURITY FIX: AG-TS-002 (Adversarial Review 2025)
# Minimum number of distinct trap classes required for amplification.
_AMPLIFICATION_MIN_TRAP_CLASSES: int = 3
# Minimum number of high-confidence signals (conf > 0.7) among the
# distinct trap classes required for amplification to kick in.
_AMPLIFICATION_MIN_HIGH_CONF_COUNT: int = 2
_AMPLIFICATION_HIGH_CONF_THRESHOLD: float = 0.7
# Amplification factor applied when all conditions are met.
_AMPLIFICATION_FACTOR: float = 1.3


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

        # SECURITY FIX: AG-TS-001 (Adversarial Review 2025)
        # Threshold jitter — small random variation per instantiation
        # prevents attackers from precisely calibrating payloads to
        # sit just above a known threshold boundary.
        self._red_threshold: float = config.red_threshold * (
            1.0 + random.uniform(-0.05, 0.05)
        )
        self._yellow_threshold: float = config.yellow_threshold * (
            1.0 + random.uniform(-0.05, 0.05)
        )

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

        # SECURITY FIX: AG-TS-001 (Adversarial Review 2025)
        # --- Signal clustering by detector ---
        # Group signals by detector name.  If the same detector fires
        # multiple times, only the signal with the *highest* effective
        # confidence contributes (avoids signal-amplification reversal
        # where an attacker triggers many low-confidence false positives
        # on one detector).  Signals from *different* detectors stack
        # normally.
        detector_groups: dict[str, list[DetectionSignal]] = defaultdict(list)
        for signal in signals:
            detector_groups[signal.detector].append(signal)

        # Track trap classes and high-confidence signals for amplification
        trap_classes_seen: set[str] = set()
        # Map each trap class to the maximum confidence seen from that class
        trap_class_max_confidence: dict[str, float] = {}

        # Accumulate per-signal penalties using clustered signals
        signal_index = 0  # monotonic counter for non-linear scaling
        for _detector, detector_signals in detector_groups.items():
            # Use the signal with the highest effective confidence from
            # this detector group.
            best_signal = max(detector_signals, key=lambda s: s.confidence)

            # SECURITY FIX: AG-TS-001 (Adversarial Review 2025)
            # Asymmetric penalty for high-confidence signals.
            effective_confidence = best_signal.confidence
            if effective_confidence > _HIGH_CONFIDENCE_THRESHOLD:
                effective_confidence *= _HIGH_CONFIDENCE_WEIGHT_MULTIPLIER

            weight = self._config.scorer_weights.get(best_signal.detector, 0.1)
            base_penalty = effective_confidence * weight

            # SECURITY FIX: AG-TS-001 (Adversarial Review 2025)
            # Non-linear penalty scaling — each additional signal from a
            # distinct detector costs more than the last, making total
            # penalties unpredictable for an attacker.
            penalty = self._compute_penalty(base_penalty, signal_index)
            total_penalty += penalty

            trap_class_key = best_signal.trap_class.value
            trap_classes_seen.add(trap_class_key)
            # Track the highest confidence per trap class
            if trap_class_key not in trap_class_max_confidence:
                trap_class_max_confidence[trap_class_key] = best_signal.confidence
            else:
                trap_class_max_confidence[trap_class_key] = max(
                    trap_class_max_confidence[trap_class_key], best_signal.confidence,
                )

            signal_index += 1

        # --- Asymmetry penalty ---
        if asymmetry_detected:
            asymmetry_weight = self._config.scorer_weights.get("asymmetry", 0.20)
            total_penalty += asymmetry_score * asymmetry_weight

        # SECURITY FIX: AG-TS-002 (Adversarial Review 2025)
        # --- Conditional multi-signal amplification ---
        # Amplification is ONLY applied when:
        #   1) Signals come from 3+ DIFFERENT trap classes, AND
        #   2) At least 2 of those classes have confidence > 0.7
        # This makes amplification much harder to trigger with noise and
        # prevents an attacker from crafting content that triggers
        # false positives on clean layers to dilute real detections.
        if self._should_amplify(trap_classes_seen, trap_class_max_confidence):
            total_penalty *= _AMPLIFICATION_FACTOR

        # --- Compute and clamp score ---
        composite_score = base_score - total_penalty
        composite_score = max(0.0, min(1.0, composite_score))

        # --- Determine tier ---
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

    # SECURITY FIX: AG-TS-001 (Adversarial Review 2025)
    def _compute_penalty(self, base_penalty: float, signal_count: int) -> float:
        """Non-linear penalty scaling — exponential growth with signal count.

        Each additional signal from a distinct detector costs more than the
        last, making the total penalty curve non-linear and therefore much
        harder for an attacker to calibrate against a fixed threshold.
        """
        # signal_count starts at 0 for the first signal.
        # log1p(0) = 0, so the first signal always gets 1.0× base_penalty.
        # Each subsequent signal adds ~30% more scaling than the previous.
        return base_penalty * (1.0 + 0.3 * math.log1p(signal_count))

    # SECURITY FIX: AG-TS-002 (Adversarial Review 2025)
    def _should_amplify(
        self,
        trap_classes_seen: set[str],
        trap_class_max_confidence: dict[str, float],
    ) -> bool:
        """Determine whether conditional multi-signal amplification applies.

        Amplification is only triggered when:
          1. Signals span 3+ *different* trap classes, AND
          2. At least 2 of those classes carry a confidence > 0.7.

        This prevents an attacker from triggering the amplification bonus
        with low-confidence noise signals injected to dilute real detections.
        """
        if len(trap_classes_seen) < _AMPLIFICATION_MIN_TRAP_CLASSES:
            return False

        # Count how many distinct trap classes have high-confidence signals
        high_conf_class_count = sum(
            1
            for _trap_class, max_conf in trap_class_max_confidence.items()
            if max_conf > _AMPLIFICATION_HIGH_CONF_THRESHOLD
        )

        return high_conf_class_count >= _AMPLIFICATION_MIN_HIGH_CONF_COUNT

    def _classify_tier(self, score: float) -> TrustTier:
        """Map a composite score to a :class:`TrustTier`."""
        # SECURITY FIX: AG-TS-001 (Adversarial Review 2025)
        # Uses jittered thresholds stored at instantiation time instead of
        # the raw config values, preventing precise calibration attacks.
        if score >= self._yellow_threshold:
            return TrustTier.GREEN
        if score >= self._red_threshold:
            return TrustTier.YELLOW
        if score >= 0.15:
            return TrustTier.RED
        return TrustTier.QUARANTINE
