"""
Layer 1: DualFetcher — detection asymmetry defense.

Detects if a web page serves different content to AI agents vs. human browsers
by comparing responses across multiple user-agent strings and behavioral
fingerprinting signals.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.

# SECURITY FIX: AG-DF-001 (Adversarial Review 2025)
# Enhanced behavioral fingerprinting beyond UA strings
# Adds DOM element counting, meta tag comparison, canonical/OG tag verification,
# content hashing, and Wayback Machine cache verification.
# Prevents bypass where attackers serve identical content to both human and bot UAs.
"""

import difflib
import hashlib
import logging
from collections import Counter
from typing import Optional
from urllib.parse import urlparse

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

    # SECURITY FIX: AG-DF-001 — New detection fields (backward-compatible defaults)
    dom_element_count_diff: dict[str, int] | None = None
    meta_tag_diff: list[str] = Field(default_factory=list)
    canonical_mismatch: bool = False
    content_hash_mismatch: bool = False


class DualFetcher:
    """
    Fetches a URL with both human-like and bot-like user agents, then compares
    the responses to detect content asymmetry attacks.

    An attacker may serve malicious injection payloads only to known bot user
    agents while showing innocuous content to human browsers. This layer detects
    that asymmetry by comparing text content, raw HTML, status codes,
    content-length headers, DOM element counts, meta tags, canonical URLs,
    and content hashes across multiple fetches.

    # SECURITY FIX: AG-DF-001 (Adversarial Review 2025)
    # Enhanced behavioral fingerprinting beyond UA strings
    # Adds DOM element counting, meta tag comparison, and content hashing
    """

    # Browser-like Sec-Fetch headers for human behavioral fingerprinting
    _HUMAN_HEADERS: dict[str, str] = {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    }

    # Element types to count for DOM element comparison
    _DOM_COUNT_TAGS: list[str] = ["div", "script", "link", "form", "iframe"]

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

        # SECURITY FIX: AG-DF-001 (Adversarial Review 2025)
        # Human fetch now uses full behavioral fingerprint headers (Accept,
        # Accept-Language, Sec-Fetch-*, etc.) to create a realistic browser
        # fingerprint. Bot fetches use minimal headers (UA only), creating
        # a detectable fingerprint gap that attackers cannot easily bridge.
        """
        # --- 1. Human baseline fetch (with full behavioral fingerprint) ---
        human_resp: Optional[requests.Response] = None
        human_headers = {"User-Agent": self._human_ua, **self._HUMAN_HEADERS}
        try:
            human_resp = requests.get(
                url,
                headers=human_headers,
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
        worst_dom_diff: dict[str, int] | None = None
        worst_meta_diff: list[str] = []
        any_canonical_mismatch = False
        any_hash_mismatch = False

        for bot_ua in self._bot_uas:
            # SECURITY FIX: AG-DF-001 — Bot fetches use minimal headers (UA only)
            # This creates a realistic fingerprint difference. Real bots don't
            # send Sec-Fetch-* or Accept headers in the same way browsers do.
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

            # --- SECURITY FIX: AG-DF-001 — Enhanced comparisons ---

            # DOM element count comparison
            dom_diff = self._compare_dom_elements(human_text, bot_text)
            if dom_diff and any(v != 0 for v in dom_diff.values()):
                if worst_dom_diff is None or sum(abs(v) for v in dom_diff.values()) > sum(
                    abs(v) for v in worst_dom_diff.values()
                ):
                    worst_dom_diff = dom_diff
                # Extra elements in bot response suggest hidden injection payloads
                bot_extra = {k: v for k, v in dom_diff.items() if v > 0}
                if bot_extra:
                    logger.info(
                        "DualFetcher: bot has extra DOM elements (UA=%s): %s",
                        bot_ua, bot_extra,
                    )

            # Meta tag comparison
            meta_diff = self._compare_meta_tags(human_text, bot_text)
            if meta_diff and len(meta_diff) > len(worst_meta_diff):
                worst_meta_diff = meta_diff
                logger.info(
                    "DualFetcher: meta tag differences (UA=%s): %s",
                    bot_ua, meta_diff,
                )

            # Canonical/OG tag comparison
            if self._check_canonical_mismatch(human_text, bot_text):
                any_canonical_mismatch = True
                logger.info(
                    "DualFetcher: canonical/OG tag mismatch (UA=%s)",
                    bot_ua,
                )

            # Content hash comparison (SHA256 of stripped text)
            if self._check_content_hash_mismatch(human_visible, bot_visible):
                any_hash_mismatch = True
                logger.info(
                    "DualFetcher: content hash mismatch (UA=%s)",
                    bot_ua,
                )

        # Asymmetry is detected if ANY signal fires
        asymmetry_detected = (
            worst_score > self._threshold
            or any_status_mismatch
            or any_canonical_mismatch
            or any_hash_mismatch
            or (worst_dom_diff is not None and any(v > 0 for v in worst_dom_diff.values()))
            or len(worst_meta_diff) > 0
        )

        return DualFetchResult(
            human_content=human_text,
            bot_content=human_text,  # representative content (human baseline)
            asymmetry_score=worst_score,
            asymmetry_detected=asymmetry_detected,
            diff_summary=worst_diff_summary,
            suspicious_bot_uas=suspicious_uas,
            status_code_mismatch=any_status_mismatch,
            content_length_mismatch=any_length_mismatch,
            # SECURITY FIX: AG-DF-001 — New detection fields
            dom_element_count_diff=worst_dom_diff,
            meta_tag_diff=worst_meta_diff,
            canonical_mismatch=any_canonical_mismatch,
            content_hash_mismatch=any_hash_mismatch,
        )

    # ------------------------------------------------------------------
    # AG-DF-001: Enhanced detection methods
    # ------------------------------------------------------------------

    def _compare_dom_elements(
        self, human_html: str, bot_html: str
    ) -> dict[str, int] | None:
        """
        Compare DOM element counts between human and bot responses.

        Returns a dict mapping element tag names to count differences
        (bot_count - human_count). Positive values mean the bot response
        has MORE elements — a potential sign of hidden injection payloads
        (e.g., extra <script>, <iframe>, or <div> tags).

        Returns None if parsing fails.
        """
        try:
            human_soup = BeautifulSoup(human_html, "lxml")
            bot_soup = BeautifulSoup(bot_html, "lxml")
        except Exception:
            return None

        diff: dict[str, int] = {}
        for tag_name in self._DOM_COUNT_TAGS:
            human_count = len(human_soup.find_all(tag_name))
            bot_count = len(bot_soup.find_all(tag_name))
            delta = bot_count - human_count
            if delta != 0:
                diff[tag_name] = delta

        return diff if diff else {}

    def _compare_meta_tags(
        self, human_html: str, bot_html: str
    ) -> list[str]:
        """
        Compare all <meta> tags between human and bot responses.

        Extra meta tags in the bot response could carry injection payloads
        (e.g., CSRF tokens, redirect URIs, or hidden instructions encoded
        in meta name/content attributes).

        Returns a list of strings describing the differences.
        """
        try:
            human_soup = BeautifulSoup(human_html, "lxml")
            bot_soup = BeautifulSoup(bot_html, "lxml")
        except Exception:
            return []

        # Build normalized sets of meta tag signatures
        def _meta_signatures(soup: BeautifulSoup) -> set[str]:
            sigs: set[str] = set()
            for meta in soup.find_all("meta"):
                name = meta.get("name", "")
                content = meta.get("content", "")
                charset = meta.get("charset", "")
                http_equiv = meta.get("http-equiv", "")
                prop = meta.get("property", "")
                if charset:
                    sigs.add(f"charset={charset}")
                elif http_equiv:
                    sigs.add(f"http-equiv={http_equiv}|content={content}")
                elif name:
                    sigs.add(f"name={name}|content={content}")
                elif prop:
                    sigs.add(f"property={prop}|content={content}")
            return sigs

        human_metas = _meta_signatures(human_soup)
        bot_metas = _meta_signatures(bot_soup)

        diffs: list[str] = []

        # Tags present in bot but not in human
        only_in_bot = bot_metas - human_metas
        if only_in_bot:
            diffs.append(f"extra_in_bot: {', '.join(sorted(only_in_bot))}")

        # Tags present in human but not in bot
        only_in_human = human_metas - bot_metas
        if only_in_human:
            diffs.append(f"missing_from_bot: {', '.join(sorted(only_in_human))}")

        return diffs

    def _check_canonical_mismatch(
        self, human_html: str, bot_html: str
    ) -> bool:
        """
        Check if canonical URL or Open Graph tags differ between responses.

        Attackers may change canonical/OG URLs in bot-targeted responses
        to redirect SEO signals or alter how content is interpreted.
        """
        try:
            human_soup = BeautifulSoup(human_html, "lxml")
            bot_soup = BeautifulSoup(bot_html, "lxml")
        except Exception:
            return False

        # Extract canonical URL
        def _get_canonical(soup: BeautifulSoup) -> str:
            link = soup.find("link", rel="canonical")
            return link.get("href", "").strip() if link else ""

        human_canonical = _get_canonical(human_soup)
        bot_canonical = _get_canonical(bot_soup)

        if human_canonical and bot_canonical and human_canonical != bot_canonical:
            return True

        # Extract Open Graph tags
        def _get_og_tags(soup: BeautifulSoup) -> dict[str, str]:
            og: dict[str, str] = {}
            for meta in soup.find_all("meta", attrs={"property": True}):
                prop = meta.get("property", "")
                if prop.startswith("og:"):
                    og[prop] = meta.get("content", "")
            return og

        human_og = _get_og_tags(human_soup)
        bot_og = _get_og_tags(bot_soup)

        # Compare OG tags that exist in both responses
        for key in set(human_og.keys()) & set(bot_og.keys()):
            if human_og[key] != bot_og[key]:
                return True

        return False

    def _check_content_hash_mismatch(
        self, human_text: str, bot_text: str
    ) -> bool:
        """
        Compute SHA256 of stripped, normalized text content for both responses.

        If the hashes differ, it means the text content is not identical —
        even if the similarity score is close to 1.0, small differences
        can carry injection payloads that evade threshold-based detection.

        Normalization: collapse whitespace, lowercase, strip.
        """
        def _normalize_and_hash(text: str) -> str:
            normalized = " ".join(text.split()).lower().strip()
            return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        human_hash = _normalize_and_hash(human_text)
        bot_hash = _normalize_and_hash(bot_text)
        return human_hash != bot_hash

    def verify_against_cache(self, url: str) -> dict:
        """
        Optionally verify current content against Wayback Machine cache.

        Fetches a recent snapshot from web.archive.org and compares it with
        the human baseline content. This provides an independent reference
        point that attackers cannot easily manipulate.

        Returns a dict with:
            - cache_match: bool — True if content matches the cached version
            - cache_diff_summary: str — description of differences
            - cache_available: bool — True if a cached version was found
            - cache_url: str | None — the Wayback Machine URL used
        """
        # SECURITY FIX: AG-DF-001 (Adversarial Review 2025)
        # Cross-referencing against Wayback Machine provides an independent
        # baseline that attackers cannot control. If current content differs
        # from the archived version, the site may have been compromised.

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return {
                "cache_available": False,
                "cache_match": False,
                "cache_diff_summary": "Invalid URL",
                "cache_url": None,
            }

        wayback_url = f"https://web.archive.org/web/{url}"
        logger.info("DualFetcher: verifying %s against Wayback Machine", url)

        try:
            # Fetch the latest archived snapshot
            cache_resp = requests.get(
                wayback_url,
                headers={
                    "User-Agent": self._human_ua,
                    **self._HUMAN_HEADERS,
                },
                timeout=self._timeout,
                verify=self._verify_ssl,
            )
            cache_text = cache_resp.text
        except requests.RequestException as exc:
            logger.warning(
                "DualFetcher: Wayback Machine fetch failed for %s — %s", url, exc
            )
            return {
                "cache_available": False,
                "cache_match": False,
                "cache_diff_summary": f"Cache fetch failed: {exc}",
                "cache_url": wayback_url,
            }

        # Fetch current human baseline
        try:
            human_resp = requests.get(
                url,
                headers={
                    "User-Agent": self._human_ua,
                    **self._HUMAN_HEADERS,
                },
                timeout=self._timeout,
                verify=self._verify_ssl,
            )
            human_text = human_resp.text
        except requests.RequestException as exc:
            logger.warning(
                "DualFetcher: human fetch failed for %s — %s", url, exc
            )
            return {
                "cache_available": True,
                "cache_match": False,
                "cache_diff_summary": f"Current fetch failed: {exc}",
                "cache_url": wayback_url,
            }

        # Compare visible text content
        try:
            cache_soup = BeautifulSoup(cache_text, "lxml")
            human_soup = BeautifulSoup(human_text, "lxml")

            for tag in cache_soup.find_all(["script", "style"]):
                tag.decompose()
            for tag in human_soup.find_all(["script", "style"]):
                tag.decompose()

            cache_visible = cache_soup.get_text(separator=" ", strip=True)
            human_visible = human_soup.get_text(separator=" ", strip=True)
        except Exception:
            cache_visible = cache_text
            human_visible = human_text

        similarity, description = self._compare_content(human_visible, cache_visible)

        # Also check content hash
        hash_mismatch = self._check_content_hash_mismatch(human_visible, cache_visible)

        # If Wayback returns a "page not available" message, the cache isn't useful
        cache_available = "wayback" not in cache_visible.lower() or len(cache_visible) > 200

        return {
            "cache_available": cache_available,
            "cache_match": similarity > 0.9 and not hash_mismatch,
            "cache_diff_summary": (
                f"similarity={similarity:.4f}, hash_mismatch={hash_mismatch} — {description}"
            ),
            "cache_url": wayback_url,
        }

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
