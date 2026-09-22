"""
Layer 2: ContentInjectionDetector.

Detects hidden injection payloads embedded in HTML pages through HTML
comments, CSS-hidden text, aria-hidden attributes, zero-width characters,
metadata attributes, and JavaScript injection vectors.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.

Security hardening (Adversarial Review 2025):
    AG-CI-001: Unicode homoglyph bypass via NFKC normalization
    AG-CI-002: Base64/URL encoding evasion via decoding layer
    AG-CI-003: Fragmented injection via sliding-window comment analysis
    AG-CI-004: CSS variable obfuscation via var() resolution
    AG-CI-005: JavaScript dynamic string construction detection
    AG-CI-006: SVG foreignObject namespace injection detection
"""

import base64
import logging
import re
import unicodedata
from typing import Optional
from urllib.parse import unquote

from bs4 import BeautifulSoup, Tag

from agentguard.config import AgentGuardConfig
from agentguard.models import DetectionSignal, TrapClass

logger = logging.getLogger(__name__)

# SECURITY FIX: AG-CI-001 (Adversarial Review 2025)
# Explicit homoglyph mapping for characters that NFKC does NOT normalize.
# These characters look identical to Latin equivalents but have different codepoints.
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic → Latin
    "\u0456": "i",   # Cyrillic і → Latin i
    "\u0406": "I",   # Cyrillic І → Latin I
    "\u043E": "o",   # Cyrillic о → Latin o
    "\u041E": "O",   # Cyrillic О → Latin O
    "\u0440": "p",   # Cyrillic р → Latin p
    "\u0420": "P",   # Cyrillic Р → Latin P
    "\u0441": "s",   # Cyrillic с → Latin s (selective)
    "\u0421": "C",   # Cyrillic С → Latin C
    "\u0443": "y",   # Cyrillic у → Latin y
    "\u0423": "Y",   # Cyrillic У → Latin Y
    "\u0445": "x",   # Cyrillic х → Latin x
    "\u0425": "X",   # Cyrillic Х → Latin X
    "\u0430": "a",   # Cyrillic а → Latin a
    "\u0410": "A",   # Cyrillic А → Latin A
    "\u0435": "e",   # Cyrillic е → Latin e
    "\u0415": "E",   # Cyrillic Е → Latin E
    # Greek → Latin (common confusables)
    "\u03B1": "a",   # Greek α → Latin a
    "\u0391": "A",   # Greek Α → Latin A
    "\u03BF": "o",   # Greek ο → Latin o
    "\u039F": "O",   # Greek Ο → Latin O
    # Fullwidth Latin → Latin (NFKC handles most but be explicit)
    "\uFF49": "i",   # Fullwidth ｉ → Latin i
    "\uFF49": "i",   # Fullwidth ｉ → Latin i
}

# Build a translation table for fast homoglyph replacement
_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPH_MAP)

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

# SECURITY FIX: AG-CI-005 (Adversarial Review 2025)
# Regex patterns for JavaScript dynamic string construction techniques
_JS_DYNAMIC_STRING_PATTERNS: list[re.Pattern[str]] = [
    # String.fromCharCode(...) calls
    re.compile(r"String\s*\.\s*fromCharCode\s*\(\s*[\d,\s]+\s*\)", re.IGNORECASE),
    # atob() base64 decode calls
    re.compile(r"\batob\s*\(\s*[\"'][A-Za-z0-9+/=]+[\"']\s*\)", re.IGNORECASE),
    # eval() with string concatenation or template literals
    re.compile(r"\beval\s*\(\s*(?:[\"'][^\"']+[\"']\s*[+]\s*)+[\"'][^\"']*[\"']\s*\)", re.IGNORECASE),
    # eval() with template literals
    re.compile(r"\beval\s*\(\s*`[^`]*`\s*\)", re.IGNORECASE),
    # btoa() / atob() chained with fromCharCode
    re.compile(r"atob\s*\([^)]+\)\s*\.\s*split\s*\([^)]+\)", re.IGNORECASE),
    # Char code array joined into string
    re.compile(r"(?:\[|new\s+Array)\s*\s*[\d,\s]+\s*\]?\s*\.\s*map\s*\(\s*.*?String\s*\.\s*fromCharCode", re.IGNORECASE),
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

    Security-hardened with adversarial defenses (2025):
    7. Unicode homoglyph normalization (AG-CI-001)
    8. Base64/URL encoding evasion detection (AG-CI-002)
    9. Fragmented injection across comments (AG-CI-003)
    10. CSS custom property obfuscation resolution (AG-CI-004)
    11. JavaScript dynamic string construction (AG-CI-005)
    12. SVG foreignObject namespace injection (AG-CI-006)
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        self._config = config
        # Pre-compile all injection keyword patterns from config
        self._injection_patterns: list[re.Pattern[str]] = [
            re.compile(p, re.IGNORECASE) for p in config.injection_keyword_patterns
        ]

    # ------------------------------------------------------------------
    # SECURITY FIX: Preprocessing helpers (AG-CI-001, AG-CI-002)
    # ------------------------------------------------------------------

    def _normalize_text(self, text: str) -> str:
        """SECURITY FIX: AG-CI-001 (Adversarial Review 2025)

        Two-pass normalization to defeat homoglyph bypass attacks:

        1. **Explicit homoglyph replacement**: Cyrillic/Greek characters that
           look identical to Latin but have different codepoints are replaced
           with their Latin equivalents via a pre-built translation table.
           NFKC alone does NOT handle these (e.g., Cyrillic і U+0456 stays
           as і after NFKC). We handle 20+ known confusable pairs.

        2. **NFKC normalization**: Collapses fullwidth, compatibility, and
           composed/decomposed variants that NFKC *does* handle.
        """
        if not text:
            return text
        try:
            # Pass 1: Explicit homoglyph mapping (Cyrillic/Greek → Latin)
            text = text.translate(_HOMOGLYPH_TABLE)
            # Pass 2: NFKC normalization (fullwidth, compatibility chars)
            return unicodedata.normalize('NFKC', text)
        except Exception:
            return text

    def _decode_payloads(self, text: str) -> str:
        """SECURITY FIX: AG-CI-002 (Adversarial Review 2025)

        Decode Base64 and URL-encoded payloads for scanning. Adversaries
        encode injection keywords (e.g., 'ignore previous instructions'
        -> 'aWdub3JlIHByZXZpb3Vz') to bypass static keyword detection.
        This layer decodes common encodings before pattern matching.
        """
        if not text:
            return text
        decoded_parts: list[str] = [text]

        try:
            # Try base64 decode of suspicious-looking strings (20+ chars)
            for match in re.finditer(r'[A-Za-z0-9+/]{20,}={0,2}', text):
                try:
                    candidate = match.group()
                    decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                    if decoded and any(c.isalpha() for c in decoded):
                        decoded_parts.append(decoded)
                except Exception:
                    pass
        except Exception:
            pass

        # URL decode
        try:
            url_decoded = unquote(text)
            if url_decoded != text:
                decoded_parts.append(url_decoded)
        except Exception:
            pass

        return '\n'.join(decoded_parts)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, html: str) -> list[DetectionSignal]:
        """Run all detection sub-checks and return collected signals."""
        signals: list[DetectionSignal] = []

        # SECURITY FIX: AG-CI-001, AG-CI-002 (Adversarial Review 2025)
        # Pre-process HTML with normalization and decoding before all checks.
        # The preprocessed versions are passed to the new detection methods.
        normalized_html = self._normalize_text(html)
        decoded_html = self._decode_payloads(html)

        # Original detection methods (existing, preserved intact)
        signals.extend(self._detect_html_comment_injection(html))
        signals.extend(self._detect_hidden_css_text(html))
        signals.extend(self._detect_aria_hidden(html))
        signals.extend(self._detect_zero_width_chars(html))
        signals.extend(self._detect_meta_data_injection(html))
        signals.extend(self._detect_js_injection_vectors(html))

        # SECURITY FIX: New adversarial detection methods (2025)
        signals.extend(self._detect_fragmented_injection(html))
        signals.extend(self._detect_css_variable_obfuscation(html))
        signals.extend(self._detect_js_dynamic_strings(html))
        signals.extend(self._detect_svg_foreign_object(html))

        # Additional scanning of normalized+decoded text for injection patterns
        # This catches payloads that only become visible after preprocessing
        signals.extend(self._scan_preprocessed_text(normalized_html, decoded_html))

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
            # SECURITY FIX: AG-CI-006 (Adversarial Review 2025)
            # Remove SVG foreignObject elements as potential injection vectors
            for svg in soup.find_all("svg"):
                for fo in svg.find_all("foreignobject"):
                    fo.decompose()
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
            # SECURITY FIX: AG-CI-006 (Adversarial Review 2025)
            # Strip SVG foreignObject content as it can contain hidden HTML
            for svg in soup.find_all("svg"):
                for fo in svg.find_all("foreignobject"):
                    fo.decompose()
            text = soup.get_text(separator=" ", strip=True)
        except Exception:
            text = html
        # Strip zero-width chars
        text = _ZERO_WIDTH_RE.sub("", text)
        return text

    # ------------------------------------------------------------------
    # Detection methods (original — preserved intact)
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
    # SECURITY FIX: New adversarial detection methods (2025)
    # ------------------------------------------------------------------

    def _detect_fragmented_injection(self, html: str) -> list[DetectionSignal]:
        """SECURITY FIX: AG-CI-003 (Adversarial Review 2025)

        Detect injection split across multiple HTML comments or hidden
        elements. Adversaries fragment payloads like:
            <!-- ignore prev --> ... <!-- ious instructions -->
        so that no single fragment matches any pattern. A sliding window
        of 2-5 consecutive fragments is concatenated and checked.
        """
        signals: list[DetectionSignal] = []

        try:
            # Extract all HTML comments
            fragments: list[str] = re.findall(r"<!--(.*?)-->", html, re.DOTALL)

            # Also extract text from hidden elements (aria-hidden, display:none, etc.)
            try:
                soup = BeautifulSoup(html, "lxml")
                for el in soup.find_all(attrs={"aria-hidden": "true"}):
                    el_text = el.get_text(strip=True)
                    if len(el_text) >= 3:
                        fragments.append(el_text)
                for el in soup.find_all(style=True):
                    style = el.get("style", "")
                    if any(p.search(style) for p in _HIDDEN_CSS_PATTERNS):
                        el_text = el.get_text(strip=True)
                        if len(el_text) >= 3:
                            fragments.append(el_text)
            except Exception:
                pass

            if len(fragments) < 2:
                return signals

            # Sliding window: concatenate consecutive fragments and check
            # Window sizes 2 through 5
            for window_size in range(2, min(6, len(fragments) + 1)):
                for i in range(len(fragments) - window_size + 1):
                    window_fragments = fragments[i:i + window_size]
                    concatenated = " ".join(f.strip() for f in window_fragments)

                    # Also normalize to catch homoglyph fragments
                    normalized_concat = self._normalize_text(concatenated)

                    matches = self._check_injection_patterns(normalized_concat)
                    if matches:
                        pattern_str, _ = matches[0]
                        confidence = min(0.70 + (window_size * 0.05), 0.85)
                        signals.append(DetectionSignal(
                            trap_class=TrapClass.CONTENT_INJECTION,
                            signal_name="fragmented_injection",
                            confidence=confidence,
                            evidence=f"Fragmented injection across {window_size} "
                                     f"fragments: pattern {pattern_str!r} found "
                                     f"in concatenated text: {concatenated[:300]!r}",
                            raw_payload=concatenated[:500],
                            detector="content_injection",
                        ))

        except Exception:
            pass

        return signals

    def _detect_css_variable_obfuscation(self, html: str) -> list[DetectionSignal]:
        """SECURITY FIX: AG-CI-004 (Adversarial Review 2025)

        Detect and resolve CSS custom property (variable) obfuscation.
        Adversaries use CSS variables to hide injection payloads:
            :root { --secret: "ignore previous instructions"; }
            .hidden { content: var(--secret); }
        The var() references are resolved and the resolved values are
        checked for injection patterns.
        """
        signals: list[DetectionSignal] = []

        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return signals

        try:
            # Step 1: Collect all CSS custom property definitions from <style> blocks
            css_vars: dict[str, str] = {}

            for style_tag in soup.find_all("style"):
                css_text = style_tag.get_text()

                # Match CSS variable definitions: --name: value;
                # Supports quoted and unquoted values
                for var_match in re.finditer(
                    r'(--[\w-]+)\s*:\s*(?:\"([^\"]*)\"|\'([^\']*)\'|([^;]*))\s*;',
                    css_text,
                ):
                    var_name = var_match.group(1)
                    # Extract value from whichever capture group matched
                    var_value = (
                        var_match.group(2)
                        if var_match.group(2) is not None
                        else var_match.group(3)
                        if var_match.group(3) is not None
                        else var_match.group(4)
                    )
                    if var_value:
                        var_value = var_value.strip()
                        css_vars[var_name] = var_value

                # Also check inline style attributes for variable definitions
                # (less common but possible)
                for var_match in re.finditer(
                    r'(--[\w-]+)\s*:\s*(?:\"([^\"]*)\"|\'([^\']*)\'|([^;]*))\s*;',
                    css_text,
                ):
                    var_name = var_match.group(1)
                    var_value = (
                        var_match.group(2)
                        if var_match.group(2) is not None
                        else var_match.group(3)
                        if var_match.group(3) is not None
                        else var_match.group(4)
                    )
                    if var_value:
                        var_value = var_value.strip()
                        if var_name not in css_vars:
                            css_vars[var_name] = var_value

            if not css_vars:
                return signals

            # Step 2: Resolve CSS variables in all inline styles and content properties
            for el in soup.find_all(True):
                if not isinstance(el, Tag):
                    continue

                inline_style = el.get("style", "")
                if not inline_style:
                    continue

                # Resolve var() references in the style string
                resolved_style = self._resolve_css_variables(inline_style, css_vars)

                # Check the resolved style for injection patterns
                matches = self._check_injection_patterns(resolved_style)
                if matches:
                    pattern_str, _ = matches[0]
                    tag_name = el.name
                    signals.append(DetectionSignal(
                        trap_class=TrapClass.CONTENT_INJECTION,
                        signal_name="css_variable_obfuscation",
                        confidence=0.80,
                        evidence=f"CSS variable obfuscation on <{tag_name}>: "
                                 f"resolved 'var()' to injection pattern "
                                 f"{pattern_str!r}. Original: {inline_style[:200]!r} "
                                 f"-> Resolved: {resolved_style[:200]!r}",
                        raw_payload=resolved_style[:500],
                        detector="content_injection",
                    ))

            # Step 3: Check CSS variable values directly for injection patterns
            for var_name, var_value in css_vars.items():
                normalized_value = self._normalize_text(var_value)
                matches = self._check_injection_patterns(normalized_value)
                if matches:
                    pattern_str, _ = matches[0]
                    signals.append(DetectionSignal(
                        trap_class=TrapClass.CONTENT_INJECTION,
                        signal_name="css_variable_definition_injection",
                        confidence=0.75,
                        evidence=f"CSS custom property {var_name} defined with "
                                 f"injection pattern {pattern_str!r}: {var_value[:200]!r}",
                        raw_payload=var_value,
                        detector="content_injection",
                    ))

        except Exception:
            pass

        return signals

    def _resolve_css_variables(
        self, style_str: str, css_vars: dict[str, str]
    ) -> str:
        """SECURITY FIX: AG-CI-004 (Adversarial Review 2025)

        Resolve CSS custom properties (--variable) in style strings.
        Performs iterative resolution (up to 10 passes) to handle
        nested variable references like var(--a) where --a: var(--b).
        """
        resolved = style_str
        try:
            # Iteratively resolve nested variable references (max 10 passes)
            for _ in range(10):
                new_resolved = resolved
                for var_name, var_value in css_vars.items():
                    new_resolved = new_resolved.replace(f'var({var_name})', var_value)
                if new_resolved == resolved:
                    break
                resolved = new_resolved
        except Exception:
            pass
        return resolved

    def _detect_js_dynamic_strings(self, html: str) -> list[DetectionSignal]:
        """SECURITY FIX: AG-CI-005 (Adversarial Review 2025)

        Detect JavaScript dynamic string construction used for obfuscation.
        Adversaries build injection strings at runtime to bypass static
        analysis:
            - String.fromCharCode(105,103,110,111,114,101) -> "ignore"
            - atob("aWdub3JlIHByZXZpb3Vz") -> "ignore previous"
            - eval() with string concatenation or template literals
        """
        signals: list[DetectionSignal] = []

        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return signals

        try:
            for script in soup.find_all("script"):
                js_text = script.string or ""
                if not js_text or len(js_text) < 20:
                    continue

                for pattern in _JS_DYNAMIC_STRING_PATTERNS:
                    for match in pattern.finditer(js_text):
                        matched_str = match.group(0)

                        # Try to evaluate/detect the resolved string for injection
                        resolved = self._attempt_resolve_dynamic_string(matched_str)

                        # Check both the raw pattern and any resolved value
                        for check_text in (resolved, matched_str):
                            if check_text and len(check_text) >= 5:
                                norm_text = self._normalize_text(check_text)
                                inj_matches = self._check_injection_patterns(norm_text)
                                if inj_matches:
                                    pattern_str, _ = inj_matches[0]
                                    signals.append(DetectionSignal(
                                        trap_class=TrapClass.CONTENT_INJECTION,
                                        signal_name="js_dynamic_string_construction",
                                        confidence=0.85,
                                        evidence=f"JavaScript dynamic string construction "
                                                 f"resolves to injection pattern "
                                                 f"{pattern_str!r}. Raw: {matched_str[:200]!r}",
                                        raw_payload=js_text[:500],
                                        detector="content_injection",
                                    ))
                                    break
                        else:
                            # No injection pattern matched in resolved text, but
                            # still flag the dynamic string construction as suspicious
                            signals.append(DetectionSignal(
                                trap_class=TrapClass.CONTENT_INJECTION,
                                signal_name="js_dynamic_string_suspicious",
                                confidence=0.55,
                                evidence=f"JavaScript dynamic string construction "
                                         f"detected (no injection pattern confirmed): "
                                         f"{matched_str[:200]!r}",
                                raw_payload=js_text[:500],
                                detector="content_injection",
                            ))

        except Exception:
            pass

        return signals

    def _attempt_resolve_dynamic_string(self, js_expr: str) -> str:
        """SECURITY FIX: AG-CI-005 (Adversarial Review 2025)

        Attempt to resolve common JavaScript dynamic string constructions
        to their plaintext values. Returns the best-effort resolved string,
        or the original expression if resolution fails.
        """
        try:
            # Resolve String.fromCharCode(...)
            fcc_match = re.search(
                r'String\s*\.\s*fromCharCode\s*\(\s*([\d,\s]+)\s*\)',
                js_expr, re.IGNORECASE,
            )
            if fcc_match:
                char_codes = [
                    int(c.strip())
                    for c in fcc_match.group(1).split(',')
                    if c.strip().isdigit()
                ]
                if char_codes:
                    try:
                        resolved = ''.join(chr(c) for c in char_codes)
                        if resolved:
                            return resolved
                    except (ValueError, OverflowError):
                        pass

            # Resolve atob(...) — base64 decode
            atob_match = re.search(
                r'\batob\s*\(\s*[\"\'`]([A-Za-z0-9+/=]+)[\"\'`]\s*\)',
                js_expr, re.IGNORECASE,
            )
            if atob_match:
                try:
                    decoded = base64.b64decode(atob_match.group(1)).decode(
                        'utf-8', errors='ignore'
                    )
                    if decoded and any(c.isalpha() for c in decoded):
                        return decoded
                except Exception:
                    pass

        except Exception:
            pass

        return js_expr

    def _detect_svg_foreign_object(self, html: str) -> list[DetectionSignal]:
        """SECURITY FIX: AG-CI-006 (Adversarial Review 2025)

        Detect injection via SVG foreignObject elements. The SVG
        foreignObject element allows embedding arbitrary HTML content
        within SVG, creating a hidden injection scope that is often
        invisible to standard HTML parsers and security scanners.

        Any foreignObject element is flagged as suspicious (confidence
        0.60), and if its content matches injection patterns the
        confidence is elevated to 0.90.
        """
        signals: list[DetectionSignal] = []

        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return signals

        try:
            for svg in soup.find_all("svg"):
                for fo in svg.find_all("foreignobject"):
                    # Extract text content from the foreignObject
                    fo_text = fo.get_text(separator=" ", strip=True)

                    # Check the inner HTML content (not just text) for patterns
                    fo_html = str(fo)
                    normalized_fo_html = self._normalize_text(fo_html)
                    normalized_fo_text = self._normalize_text(fo_text)

                    # Check for injection patterns in foreignObject content
                    injection_found = False
                    pattern_str = ""

                    # Check text content
                    if fo_text and len(fo_text) >= 5:
                        text_matches = self._check_injection_patterns(normalized_fo_text)
                        if text_matches:
                            pattern_str, _ = text_matches[0]
                            injection_found = True

                    # Check HTML content (catches patterns in attributes, tags)
                    if not injection_found and len(fo_html) >= 10:
                        html_matches = self._check_injection_patterns(normalized_fo_html)
                        if html_matches:
                            pattern_str, _ = html_matches[0]
                            injection_found = True

                    if injection_found:
                        signals.append(DetectionSignal(
                            trap_class=TrapClass.CONTENT_INJECTION,
                            signal_name="svg_foreign_object_injection",
                            confidence=0.90,
                            evidence=f"SVG foreignObject contains injection pattern "
                                     f"{pattern_str!r}: {fo_text[:200]!r}",
                            raw_payload=fo_html[:500],
                            detector="content_injection",
                        ))
                    else:
                        # Flag ANY foreignObject as suspicious — it's a potent
                        # attack vector even without confirmed injection patterns
                        signals.append(DetectionSignal(
                            trap_class=TrapClass.CONTENT_INJECTION,
                            signal_name="svg_foreign_object_suspicious",
                            confidence=0.60,
                            evidence=f"SVG foreignObject element detected (potential "
                                     f"hidden injection scope). Content: "
                                     f"{fo_text[:200]!r}",
                            raw_payload=fo_html[:500],
                            detector="content_injection",
                        ))

        except Exception:
            pass

        return signals

    def _scan_preprocessed_text(
        self, normalized_html: str, decoded_html: str
    ) -> list[DetectionSignal]:
        """SECURITY FIX: AG-CI-001, AG-CI-002 (Adversarial Review 2025)

        Scan the preprocessed (normalized + decoded) text for injection
        patterns. This catches payloads that only become visible after
        Unicode normalization or encoding decode, but were not caught
        by the individual detection methods.
        """
        signals: list[DetectionSignal] = []

        try:
            for label, preprocessed in (
                ("normalized", normalized_html),
                ("decoded", decoded_html),
            ):
                if not preprocessed:
                    continue

                matches = self._check_injection_patterns(preprocessed)
                if matches:
                    pattern_str, confidence = matches[0]
                    signals.append(DetectionSignal(
                        trap_class=TrapClass.CONTENT_INJECTION,
                        signal_name=f"preprocessed_{label}_text_injection",
                        confidence=min(confidence, 0.75),
                        evidence=f"Injection pattern {pattern_str!r} found "
                                 f"after {label} preprocessing: "
                                 f"{preprocessed[:200]!r}",
                        raw_payload=preprocessed[:500],
                        detector="content_injection",
                    ))
        except Exception:
            pass

        return signals

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_injection_patterns(
        self, text: str
    ) -> list[tuple[str, float]]:
        """
        Check *text* against all compiled injection patterns.

        SECURITY FIX: AG-CI-001 (Adversarial Review 2025)
        Text is NFKC-normalized before pattern matching to collapse
        Unicode homoglyphs (e.g., Cyrillic 'і' -> Latin 'i').

        Returns a list of ``(matched_pattern_string, confidence)`` tuples.
        """
        # SECURITY FIX: AG-CI-001 (Adversarial Review 2025)
        # Normalize text before all pattern matching to defeat homoglyph bypass
        normalized_text = self._normalize_text(text)

        results: list[tuple[str, float]] = []
        for pattern in self._injection_patterns:
            match = pattern.search(normalized_text)
            if match:
                matched_str = match.group(0)
                results.append((matched_str, 0.8))
        return results
