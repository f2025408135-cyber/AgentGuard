"""
Layer 2: ContentInjectionDetector.

Detects hidden injection payloads embedded in HTML pages through HTML
comments, CSS-hidden text, aria-hidden attributes, zero-width characters,
metadata attributes, and JavaScript injection vectors.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import logging
import re
from typing import Optional

from bs4 import BeautifulSoup, Tag

from agentguard.config import AgentGuardConfig
from agentguard.models import DetectionSignal, TrapClass

logger = logging.getLogger(__name__)

# Unicode zero-width characters used for steganographic text hiding
_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff\u00ad"

# Regex to detect zero-width characters in a string
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]")

# CSS property patterns that hide text from human visual rendering but leave
# it accessible to machines / screen-readers / bots.
_HIDDEN_CSS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"color\s*:\s*(?:white|#fff(?:ffffff)?|rgba?\(\s*255[^)]*\))", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*(?:0|0(?:\.\d+))\b", re.IGNORECASE),
    re.compile(r"font-size\s*:\s*(?:0|0(?:\.\d+)?|1px?)\b", re.IGNORECASE),
    re.compile(r"height\s*:\s*0\b", re.IGNORECASE),
    re.compile(r"width\s*:\s*0\b", re.IGNORECASE),
    re.compile(r"overflow\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"position\s*:\s*absolute", re.IGNORECASE),
    re.compile(r"left\s*:\s*-\d{4,}", re.IGNORECASE),
    re.compile(r"clip\s*:\s*rect\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)", re.IGNORECASE),
]


class ContentInjectionDetector:
    """
    Scans HTML content for six categories of hidden injection payloads:

    1. HTML comment injection
    2. CSS-hidden text (inline styles + <style> blocks)
    3. aria-hidden elements
    4. Zero-width Unicode characters
    5. Metadata / data-* attribute injection
    6. JavaScript injection vectors
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        self._config = config
        # Pre-compile all injection keyword patterns from config
        self._injection_patterns: list[re.Pattern[str]] = [
            re.compile(p, re.IGNORECASE) for p in config.injection_keyword_patterns
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, html: str) -> list[DetectionSignal]:
        """Run all six detection sub-checks and return collected signals."""
        signals: list[DetectionSignal] = []
        signals.extend(self._detect_html_comment_injection(html))
        signals.extend(self._detect_hidden_css_text(html))
        signals.extend(self._detect_aria_hidden(html))
        signals.extend(self._detect_zero_width_chars(html))
        signals.extend(self._detect_meta_data_injection(html))
        signals.extend(self._detect_js_injection_vectors(html))
        return signals

    def sanitize(self, html: str) -> str:
        """
        Remove known injection vectors from HTML:

        * Strips HTML comments
        * Removes elements with display:none / visibility:hidden
        * Strips zero-width characters
        """
        # 1. Remove HTML comments
        cleaned = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)

        # 2. Remove zero-width chars
        cleaned = _ZERO_WIDTH_RE.sub("", cleaned)

        # 3. Remove hidden elements via BeautifulSoup
        try:
            soup = BeautifulSoup(cleaned, "lxml")
            # Elements with aria-hidden
            for el in soup.find_all(attrs={"aria-hidden": "true"}):
                el.decompose()
            # Elements with display:none or visibility:hidden in inline style
            for el in list(soup.find_all(style=True)):
                style = el.get("style", "")
                if re.search(r"display\s*:\s*none|visibility\s*:\s*hidden", style, re.IGNORECASE):
                    el.decompose()
            cleaned = str(soup)
        except Exception:
            pass  # Best-effort — return what we have

        return cleaned

    def extract_visible_text(self, html: str) -> str:
        """
        Parse *html* with BeautifulSoup, strip scripts/styles, extract
        visible text, and remove zero-width characters.
        """
        try:
            soup = BeautifulSoup(html, "lxml")
            for tag in soup.find_all(["script", "style"]):
                tag.decompose()
            text = soup.get_text(separator=" ", strip=True)
        except Exception:
            text = html
        # Strip zero-width chars
        text = _ZERO_WIDTH_RE.sub("", text)
        return text

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def _detect_html_comment_injection(self, html: str) -> list[DetectionSignal]:
        """Detect injection payloads hidden inside HTML comments."""
        signals: list[DetectionSignal] = []
        comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
        for comment in comments:
            comment_text = comment.strip()
            if len(comment_text) < 10:
                continue
            matches = self._check_injection_patterns(comment_text)
            if matches:
                pattern_str, _ = matches[0]
                signals.append(DetectionSignal(
                    trap_class=TrapClass.CONTENT_INJECTION,
                    signal_name="html_comment_injection",
                    confidence=0.9,
                    evidence=f"Injection pattern in HTML comment: {pattern_str!r} "
                             f"found in {comment_text[:200]!r}",
                    raw_payload=comment_text,
                    detector="content_injection",
                ))
        return signals

    def _detect_hidden_css_text(self, html: str) -> list[DetectionSignal]:
        """
        Detect text hidden via CSS: inline styles on elements AND class rules
        defined in <style> blocks.
        """
        signals: list[DetectionSignal] = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return signals

        # --- Collect CSS class names that have hidden properties ---
        hidden_classes: set[str] = set()

        # Parse <style> blocks
        for style_tag in soup.find_all("style"):
            css_text = style_tag.get_text()
            # Find CSS rules: .classname { ... }
            for rule_match in re.finditer(
                r"([.#\w][\w-]*)\s*\{([^}]*)\}", css_text, re.DOTALL
            ):
                selector = rule_match.group(1).lstrip(".#")
                props = rule_match.group(2)
                if any(p.search(props) for p in _HIDDEN_CSS_PATTERNS):
                    hidden_classes.add(selector)

        # --- Check elements with inline styles ---
        for el in soup.find_all(True):  # all tags
            if not isinstance(el, Tag):
                continue
            text = el.get_text(strip=True)
            if len(text) < 5:
                continue

            inline_style = el.get("style", "")
            is_hidden = False

            if inline_style:
                # Check combined inline conditions:
                # - simple hidden properties
                if any(p.search(inline_style) for p in _HIDDEN_CSS_PATTERNS[:4]):
                    is_hidden = True
                # - height:0 + overflow:hidden
                if (re.search(r"height\s*:\s*0", inline_style, re.IGNORECASE)
                        and re.search(r"overflow\s*:\s*hidden", inline_style, re.IGNORECASE)):
                    is_hidden = True
                # - position:absolute + left:-XXXX (4+ digits)
                if (re.search(r"position\s*:\s*absolute", inline_style, re.IGNORECASE)
                        and re.search(r"left\s*:\s*-\d{4,}", inline_style, re.IGNORECASE)):
                    is_hidden = True
                # - clip:rect(0,0,0,0)
                if re.search(r"clip\s*:\s*rect\s*\(\s*0", inline_style, re.IGNORECASE):
                    is_hidden = True

            # Check if element's class matches a hidden CSS class
            el_classes = el.get("class", [])
            if not is_hidden and el_classes:
                for cls in el_classes:
                    if cls in hidden_classes:
                        is_hidden = True
                        break

            if is_hidden:
                matches = self._check_injection_patterns(text)
                if matches:
                    pattern_str, _ = matches[0]
                    signals.append(DetectionSignal(
                        trap_class=TrapClass.CONTENT_INJECTION,
                        signal_name="hidden_css_text",
                        confidence=0.85,
                        evidence=f"Hidden text via CSS (class={el_classes}, "
                                 f"style={inline_style[:100]}): "
                                 f"pattern {pattern_str!r} in {text[:200]!r}",
                        raw_payload=text,
                        detector="content_injection",
                    ))

        return signals

    def _detect_aria_hidden(self, html: str) -> list[DetectionSignal]:
        """Detect injection payloads in aria-hidden="true" elements."""
        signals: list[DetectionSignal] = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return signals

        for el in soup.find_all(attrs={"aria-hidden": "true"}):
            text = el.get_text(strip=True)
            if len(text) < 10:
                continue
            matches = self._check_injection_patterns(text)
            if matches:
                pattern_str, _ = matches[0]
                signals.append(DetectionSignal(
                    trap_class=TrapClass.CONTENT_INJECTION,
                    signal_name="aria_hidden_injection",
                    confidence=0.75,
                    evidence=f"aria-hidden element with injection pattern "
                             f"{pattern_str!r}: {text[:200]!r}",
                    raw_payload=text,
                    detector="content_injection",
                ))
        return signals

    def _detect_zero_width_chars(self, html: str) -> list[DetectionSignal]:
        """Detect zero-width Unicode characters encoding hidden text."""
        signals: list[DetectionSignal] = []

        # Find all zero-width chars in the text
        zw_positions: list[tuple[int, str]] = []
        for i, ch in enumerate(html):
            if ch in _ZERO_WIDTH_CHARS:
                zw_positions.append((i, ch))

        if len(zw_positions) <= 5:
            return signals

        # Extract the zero-width chars and try to decode any hidden message
        zw_sequence = "".join(ch for _, ch in zw_positions)

        # Also extract the surrounding context (100 chars around the first cluster)
        first_pos = zw_positions[0][0]
        context_start = max(0, first_pos - 50)
        context_end = min(len(html), first_pos + 50)
        context = html[context_start:context_end]
        # Remove ZW chars from context for readability
        clean_context = _ZERO_WIDTH_RE.sub("", context)

        # Check decoded/clean context for injection patterns
        matches = self._check_injection_patterns(clean_context)
        if matches:
            pattern_str, _ = matches[0]
            signals.append(DetectionSignal(
                trap_class=TrapClass.CONTENT_INJECTION,
                signal_name="zero_width_char_injection",
                confidence=0.70,
                evidence=f"Found {len(zw_positions)} zero-width chars near "
                         f"content matching {pattern_str!r}: {clean_context[:200]!r}",
                raw_payload=zw_sequence,
                detector="content_injection",
            ))

        # Also flag if massive zero-width char presence regardless of patterns
        if len(zw_positions) > 50 and not matches:
            signals.append(DetectionSignal(
                trap_class=TrapClass.CONTENT_INJECTION,
                signal_name="zero_width_char_anomaly",
                confidence=0.55,
                evidence=f"Found {len(zw_positions)} zero-width Unicode characters "
                         f"(suspicious density)",
                raw_payload=zw_sequence[:200],
                detector="content_injection",
            ))

        return signals

    def _detect_meta_data_injection(self, html: str) -> list[DetectionSignal]:
        """Detect injection in <meta> content, data-* attrs, <link> tags."""
        signals: list[DetectionSignal] = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return signals

        # Check <meta> content attributes
        for meta in soup.find_all("meta"):
            content = meta.get("content", "")
            if content and len(content) > 10:
                matches = self._check_injection_patterns(content)
                if matches:
                    pattern_str, _ = matches[0]
                    name = meta.get("name", meta.get("property", "unnamed"))
                    signals.append(DetectionSignal(
                        trap_class=TrapClass.CONTENT_INJECTION,
                        signal_name="meta_injection",
                        confidence=0.80,
                        evidence=f"Meta tag '{name}' contains injection pattern "
                                 f"{pattern_str!r}: {content[:200]!r}",
                        raw_payload=content,
                        detector="content_injection",
                    ))

        # Check data-* attributes on all elements
        for el in soup.find_all(True):
            if not isinstance(el, Tag):
                continue
            for attr_name, attr_value in el.attrs.items():
                if isinstance(attr_value, list):
                    attr_value = " ".join(str(v) for v in attr_value)
                if not isinstance(attr_value, str) or len(attr_value) < 10:
                    continue
                if attr_name.startswith("data-"):
                    matches = self._check_injection_patterns(attr_value)
                    if matches:
                        pattern_str, _ = matches[0]
                        tag_name = el.name
                        signals.append(DetectionSignal(
                            trap_class=TrapClass.CONTENT_INJECTION,
                            signal_name="data_attr_injection",
                            confidence=0.80,
                            evidence=f"data-* attribute '{attr_name}' on <{tag_name}> "
                                     f"matches {pattern_str!r}: {attr_value[:200]!r}",
                            raw_payload=attr_value,
                            detector="content_injection",
                        ))

        # Check <link> title/href attributes
        for link in soup.find_all("link"):
            title = link.get("title", "")
            href = link.get("href", "")
            for attr_val in (title, href):
                if attr_val and len(attr_val) > 10:
                    matches = self._check_injection_patterns(attr_val)
                    if matches:
                        pattern_str, _ = matches[0]
                        signals.append(DetectionSignal(
                            trap_class=TrapClass.CONTENT_INJECTION,
                            signal_name="link_attr_injection",
                            confidence=0.80,
                            evidence=f"<link> attribute contains injection pattern "
                                     f"{pattern_str!r}: {attr_val[:200]!r}",
                            raw_payload=attr_val,
                            detector="content_injection",
                        ))

        return signals

    def _detect_js_injection_vectors(self, html: str) -> list[DetectionSignal]:
        """
        Detect injection vectors within <script> blocks:

        * document.write() with suspicious content
        * innerHTML / insertAdjacentHTML with injection patterns
        * createElement + style.display='none'
        """
        signals: list[DetectionSignal] = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return signals

        for script in soup.find_all("script"):
            js_text = script.string or ""
            if not js_text:
                continue

            # Pattern 1: document.write with suspicious content
            doc_write_matches = re.findall(
                r"document\.write\s*\(\s*[\"'](.+?)[\"']\s*\)", js_text, re.DOTALL
            )
            for written in doc_write_matches:
                if len(written) > 10:
                    matches = self._check_injection_patterns(written)
                    if matches:
                        pattern_str, _ = matches[0]
                        signals.append(DetectionSignal(
                            trap_class=TrapClass.CONTENT_INJECTION,
                            signal_name="js_document_write_injection",
                            confidence=0.65,
                            evidence=f"document.write() with injection pattern "
                                     f"{pattern_str!r}: {written[:200]!r}",
                            raw_payload=js_text[:500],
                            detector="content_injection",
                        ))

            # Pattern 2: innerHTML / insertAdjacentHTML with injection patterns
            dom_insert_matches = re.findall(
                r"(?:innerHTML|insertAdjacentHTML)\s*\(\s*[\"'](?:beforeend|afterbegin|beforebegin|afterend)?[\"']\s*,\s*[\"'](.+?)[\"']\s*\)",
                js_text, re.DOTALL,
            )
            for inserted in dom_insert_matches:
                if len(inserted) > 10:
                    matches = self._check_injection_patterns(inserted)
                    if matches:
                        pattern_str, _ = matches[0]
                        signals.append(DetectionSignal(
                            trap_class=TrapClass.CONTENT_INJECTION,
                            signal_name="js_innerhtml_injection",
                            confidence=0.65,
                            evidence=f"innerHTML/insertAdjacentHTML with injection "
                                     f"pattern {pattern_str!r}: {inserted[:200]!r}",
                            raw_payload=js_text[:500],
                            detector="content_injection",
                        ))

            # Pattern 3: createElement + style.display='none'
            if re.search(
                r"createElement\s*\(.+?\)\s*.*?style\s*\.\s*display\s*=\s*['\"]?none",
                js_text, re.DOTALL | re.IGNORECASE,
            ):
                signals.append(DetectionSignal(
                    trap_class=TrapClass.CONTENT_INJECTION,
                    signal_name="js_hidden_element_creation",
                    confidence=0.65,
                    evidence="JavaScript creates element and sets display='none' — "
                             "potential hidden injection vector",
                    raw_payload=js_text[:500],
                    detector="content_injection",
                ))

        return signals

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_injection_patterns(
        self, text: str
    ) -> list[tuple[str, float]]:
        """
        Check *text* against all compiled injection patterns.

        Returns a list of ``(matched_pattern_string, confidence)`` tuples.
        """
        results: list[tuple[str, float]] = []
        for pattern in self._injection_patterns:
            match = pattern.search(text)
            if match:
                matched_str = match.group(0)
                results.append((matched_str, 0.8))
        return results
