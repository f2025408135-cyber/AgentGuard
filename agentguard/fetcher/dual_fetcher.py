"""
Layer 1: DualFetcher — detection asymmetry defense.

Detects if a web page serves different content to AI agents vs. human browsers
by comparing responses across multiple user-agent strings.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import difflib
import logging
from typing import Optional

import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from agentguard.config import AgentGuardConfig

logger = logging.getLogger(__name__)


class DualFetchResult(BaseModel):
    """Result of a dual-fetch asymmetry comparison."""

    human_content: str
    bot_content: str
    asymmetry_score: float = Field(
        ge=0.0, le=1.0,
        description="0 = identical content, 1 = completely different"
    )
    asymmetry_detected: bool = False
    diff_summary: str = ""
    suspicious_bot_uas: list[str] = Field(default_factory=list)
    status_code_mismatch: bool = False
    content_length_mismatch: bool = False


class DualFetcher:
    """
    Fetches a URL with both human-like and bot-like user agents, then compares
    the responses to detect content asymmetry attacks.

    An attacker may serve malicious injection payloads only to known bot user
    agents while showing innocuous content to human browsers. This layer detects
    that asymmetry by comparing text content, raw HTML, status codes, and
    content-length headers across multiple fetches.
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        self._config = config
        self._human_ua = config.human_user_agent
        self._bot_uas = config.bot_user_agents
        self._threshold = config.asymmetry_diff_threshold
        self._timeout = config.request_timeout
        self._verify_ssl = config.verify_ssl

    def fetch(self, url: str) -> DualFetchResult:
        """
        Fetch *url* with a human UA and each configured bot UA, then compare
        the bot responses against the human baseline.

        Returns a :class:`DualFetchResult` with a detailed asymmetry report.
        Network errors are handled gracefully — a partial result with
        ``asymmetry_detected=False`` is returned so downstream layers can
        still operate.
        """
        # --- 1. Human baseline fetch ---
        human_resp: Optional[requests.Response] = None
        try:
            human_resp = requests.get(
                url,
                headers={"User-Agent": self._human_ua},
                timeout=self._timeout,
                verify=self._verify_ssl,
            )
            human_text = human_resp.text
        except requests.RequestException as exc:
            logger.warning("DualFetcher: human fetch failed for %s — %s", url, exc)
            return DualFetchResult(
                human_content="",
                bot_content="",
                asymmetry_score=0.0,
                asymmetry_detected=False,
                diff_summary=f"Human fetch failed: {exc}",
            )

        # --- 2. Bot fetches & comparison ---
        worst_score = 0.0
        worst_diff_summary = ""
        suspicious_uas: list[str] = []
        any_status_mismatch = False
        any_length_mismatch = False

        for bot_ua in self._bot_uas:
            try:
                bot_resp = requests.get(
                    url,
                    headers={"User-Agent": bot_ua},
                    timeout=self._timeout,
                    verify=self._verify_ssl,
                )
                bot_text = bot_resp.text
            except requests.RequestException as exc:
                logger.warning(
                    "DualFetcher: bot fetch failed (UA=%s) for %s — %s",
                    bot_ua, url, exc,
                )
                continue

            # Status code comparison
            if human_resp is not None and human_resp.status_code != bot_resp.status_code:
                any_status_mismatch = True
                logger.info(
                    "DualFetcher: status mismatch human=%d bot=%d (UA=%s)",
                    human_resp.status_code, bot_resp.status_code, bot_ua,
                )

            # Content-Length header comparison
            human_cl = human_resp.headers.get("Content-Length")
            bot_cl = bot_resp.headers.get("Content-Length")
            if human_cl and bot_cl and human_cl != bot_cl:
                any_length_mismatch = True

            # --- Text-level comparison (visible content) ---
            try:
                human_soup = BeautifulSoup(human_text, "lxml")
                bot_soup = BeautifulSoup(bot_text, "lxml")

                # Strip <script> and <style> tags so we compare visible content
                for tag in human_soup.find_all(["script", "style"]):
                    tag.decompose()
                for tag in bot_soup.find_all(["script", "style"]):
                    tag.decompose()

                human_visible = human_soup.get_text(separator=" ", strip=True)
                bot_visible = bot_soup.get_text(separator=" ", strip=True)
            except Exception:
                # Fallback: raw text
                human_visible = human_text
                bot_visible = bot_text

            text_similarity, text_diff = self._compare_content(human_visible, bot_visible)
            text_diff_score = 1.0 - text_similarity

            # --- Raw HTML comparison (catches hidden-element differences) ---
            html_similarity, html_diff = self._compare_content(human_text, bot_text)
            html_diff_score = 1.0 - html_similarity

            # Use the *worse* of the two scores (more conservative)
            max_diff = max(text_diff_score, html_diff_score)

            if max_diff > worst_score:
                worst_score = max_diff
                worst_diff_summary = (
                    f"UA '{bot_ua}': text_diff={text_diff_score:.4f} "
                    f"html_diff={html_diff_score:.4f} — {text_diff}"
                )

            if max_diff > self._threshold:
                suspicious_uas.append(bot_ua)

        asymmetry_detected = worst_score > self._threshold or any_status_mismatch

        return DualFetchResult(
            human_content=human_text,
            bot_content=human_text,  # representative content (human baseline)
            asymmetry_score=worst_score,
            asymmetry_detected=asymmetry_detected,
            diff_summary=worst_diff_summary,
            suspicious_bot_uas=suspicious_uas,
            status_code_mismatch=any_status_mismatch,
            content_length_mismatch=any_length_mismatch,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compare_content(
        self, text_a: str, text_b: str
    ) -> tuple[float, str]:
        """
        Compare two text strings and return ``(similarity_ratio, diff_description)``.

        *similarity_ratio* is in [0, 1] where 1 means identical.
        *diff_description* is a human-readable summary of the differences.
        """
        if not text_a and not text_b:
            return 1.0, "Both empty"

        if not text_a or not text_b:
            return 0.0, "One response is empty"

        ratio = difflib.SequenceMatcher(None, text_a, text_b).ratio()

        # Build a concise unified-diff summary (cap at 500 chars for storage)
        diff_lines: list[str] = difflib.unified_diff(
            text_a.splitlines(keepends=True),
            text_b.splitlines(keepends=True),
            fromfile="human",
            tofile="bot",
            lineterm="",
        )
        diff_text = "\n".join(diff_lines)
        if len(diff_text) > 500:
            diff_text = diff_text[:500] + "… (truncated)"

        # Summarise: count changed lines
        added = 0
        removed = 0
        for line in diff_lines:
            if line.startswith("+") and not line.startswith("+++"):
                added += 1
            elif line.startswith("-") and not line.startswith("---"):
                removed += 1

        description = (
            f"similarity={ratio:.4f}, +{added}/-{removed} changed lines"
        )
        return ratio, description
