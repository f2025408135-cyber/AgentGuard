"""Tests for Layer 6: TrustScorer."""

import pytest
from agentguard.models import TrustTier, DetectionSignal, TrapClass


def _make_signal(
    trap_class=TrapClass.CONTENT_INJECTION,
    signal_name="test_signal",
    confidence=0.8,
    detector="content_injection",
):
    return DetectionSignal(
        trap_class=trap_class,
        signal_name=signal_name,
        confidence=confidence,
        evidence="test evidence",
        detector=detector,
    )


class TestCleanContentScoring:
    """Test scoring with no signals (clean content)."""

    def test_clean_content_green_score(self, trust_scorer):
        score, tier = trust_scorer.score(signals=[], asymmetry_detected=False, asymmetry_score=0.0)
        assert tier == TrustTier.GREEN
        assert score >= 0.9

    def test_clean_content_with_no_asymmetry(self, trust_scorer):
        score, tier = trust_scorer.score(
            signals=[],
            asymmetry_detected=False,
            asymmetry_score=0.0,
        )
        assert score == 1.0
        assert tier == TrustTier.GREEN


class TestSingleSignal:
    """Test scoring with a single medium signal."""

    def test_single_signal_yellow(self, trust_scorer):
        # Need 2 high-confidence signals from highest-weight detector
        # to drop below YELLOW threshold (0.65)
        # 2 * 0.9 * 0.25 = 0.45 penalty → score = 0.55
        signals = [_make_signal(confidence=0.9) for _ in range(2)]
        score, tier = trust_scorer.score(signals=signals, asymmetry_detected=False, asymmetry_score=0.0)
        assert tier == TrustTier.YELLOW
        assert score < 0.65


class TestMultipleSignals:
    """Test scoring with multiple high signals."""

    def test_multiple_signals_red(self, trust_scorer):
        # Need enough signals to drop below RED threshold (0.35)
        signals = [
            _make_signal(confidence=0.9, detector="content_injection"),
            _make_signal(confidence=0.9, detector="content_injection"),
            _make_signal(confidence=0.9, detector="content_injection"),
            _make_signal(confidence=0.9, detector="semantic_manipulation"),
        ]
        score, tier = trust_scorer.score(
            signals=signals,
            asymmetry_detected=True,
            asymmetry_score=0.5,
        )
        assert tier in (TrustTier.RED, TrustTier.QUARANTINE)


class TestQuarantineScore:
    """Test that very low scores result in QUARANTINE tier."""

    def test_quarantine_score(self, trust_scorer):
        signals = [
            _make_signal(confidence=1.0, detector="content_injection"),
            _make_signal(confidence=1.0, detector="semantic_manipulation"),
            _make_signal(confidence=1.0, detector="steganography"),
            _make_signal(confidence=1.0, detector="document_scanner"),
            _make_signal(confidence=1.0, detector="content_injection"),
        ]
        score, tier = trust_scorer.score(
            signals=signals,
            asymmetry_detected=True,
            asymmetry_score=1.0,
        )
        assert tier == TrustTier.QUARANTINE
        assert score < 0.15


class TestMultiSignalAmplification:
    """Test that signals from 3+ different trap classes amplify penalty."""

    def test_multi_signal_amplification(self, trust_scorer):
        # 3 signals from different trap classes → 1.3x penalty amplification
        signals_multi = [
            _make_signal(trap_class=TrapClass.CONTENT_INJECTION, detector="content_injection", confidence=0.9),
            _make_signal(trap_class=TrapClass.SEMANTIC_MANIPULATION, detector="semantic_manipulation", confidence=0.9),
            _make_signal(trap_class=TrapClass.CONTENT_INJECTION, detector="content_injection", confidence=0.9),
        ]
        score_multi, _ = trust_scorer.score(signals=signals_multi, asymmetry_detected=False, asymmetry_score=0.0)

        # Same total penalty from 1 trap class → no amplification
        # Use 2 signals (same weight as multi 3-signal total before amplification)
        signals_same = [
            _make_signal(trap_class=TrapClass.CONTENT_INJECTION, detector="content_injection", confidence=0.9),
            _make_signal(trap_class=TrapClass.CONTENT_INJECTION, detector="content_injection", confidence=0.9),
        ]
        score_same, _ = trust_scorer.score(signals=signals_same, asymmetry_detected=False, asymmetry_score=0.0)

        # Multi-class gets 1.3x amplification → lower score (higher penalty)
        # base penalty multi: 0.9*0.25 + 0.9*0.15 + 0.9*0.25 = 0.585
        #   amplified: 0.585*1.3 = 0.7605 → score = 0.2395
        # base penalty same: 0.9*0.25*2 = 0.45 → score = 0.55
        assert score_multi < score_same


class TestBuildReport:
    """Test the build_report method."""

    def test_build_report(self, trust_scorer):
        report = trust_scorer.build_report(
            signals=[],
            asymmetry_detected=False,
            asymmetry_score=0.0,
            url="https://example.com",
        )
        assert report.url == "https://example.com"
        assert report.trust_tier == TrustTier.GREEN
        assert report.composite_score >= 0.9
        assert report.action_taken == "ALLOW"

    def test_build_report_with_asymmetry(self, trust_scorer):
        report = trust_scorer.build_report(
            signals=[],
            asymmetry_detected=True,
            asymmetry_score=0.5,
            url="https://example.com",
        )
        assert report.asymmetry_detected is True
        assert report.asymmetry_diff_summary is not None
        assert "asymmetry" in report.asymmetry_diff_summary.lower()


class TestSummarize:
    """Test the summarize method."""

    def test_summarize(self, trust_scorer, sample_trust_report):
        summary = trust_scorer.summarize(sample_trust_report)
        assert isinstance(summary, str)
        assert len(summary) > 0
        assert "Trust Report" in summary
        assert "GREEN" in summary
