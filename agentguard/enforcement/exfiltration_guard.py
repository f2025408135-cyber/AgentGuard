"""
Layer 8: Exfiltration Guard.

Monitors outbound HTTP requests for data exfiltration attempts by scanning
request bodies and headers for personally identifiable information (PII),
checking destination domains against an allow-list, and flagging unusually
large payloads.

An ``intercept_and_scan`` helper can monkey-patch ``requests.Session`` to
provide automatic, transparent protection.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

from __future__ import annotations

import base64
import functools
import json
import logging
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from agentguard.config import AgentGuardConfig
from agentguard.exceptions import ExfiltrationAttemptError

if TYPE_CHECKING:
    import requests

logger = logging.getLogger(__name__)

# Headers considered sensitive — must not be forwarded to unauthorised domains.
_SENSITIVE_HEADERS: set[str] = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "www-authenticate",
}

# Threshold for "large payload" warning (10 KiB).
_PAYLOAD_SIZE_THRESHOLD: int = 10 * 1024

# SECURITY FIX: AG-EG-001 (Adversarial Review 2025)
# DNS tunneling detection: data encoded in subdomain labels.
# Legitimate subdomains are typically short (e.g. 'www', 'api', 'cdn').
# DNS tunnels use very long hex/base32/base64 labels to exfiltrate data.
_DNS_TUNNEL_PATTERN = re.compile(
    r'^(?:[a-z0-9-]{20,}\.){2,}[a-z0-9-]{3,}\\.(?:com|net|org|xyz|top|info|cc|tk|ml|ga|cf|gq|ru)$',
    re.IGNORECASE,
)
# Simpler pattern: look for a single very long subdomain label
_LONG_SUBDOMAIN_PATTERN = re.compile(
    r'^[a-z0-9]([a-z0-9-]{24,})[a-z0-9]\\.',
    re.IGNORECASE,
)

# SECURITY FIX: AG-EG-002 (Adversarial Review 2025)
# Hex-encoded data in URL paths or query strings (32+ consecutive hex chars)
_HEX_DATA_PATTERN = re.compile(
    r'(?:^|[/?=&#])[0-9a-f]{32,}(?:[/?=&#]|$)',
    re.IGNORECASE,
)
# Base64-encoded data in URL paths (long base64 strings without common URL-safe chars)
_BASE64_DATA_PATTERN = re.compile(
    r'(?:^|[/?=&])[A-Za-z0-9+/]{40,}={0,2}(?:[/?=&]|$)',
)

# Human-readable names for the default PII pattern classes.
_PII_LABELS: dict[str, str] = {
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b": "email address",
    r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b": "phone number",
    r"\b(?:\d[ -]*?){13,16}\b": "credit card number",
    r"\b[A-Z]{2}\d{6}[A-Z]\b": "passport number",
    r"(password|secret|api_key|token|bearer)\s*[:=]\s*\S+": "credential",
    r"BEGIN\s+(RSA|EC|PGP|OPENSSH)\s+PRIVATE\s+KEY": "private key",
    r"\b\d{3}-\d{2}-\d{4}\b": "SSN",
}


class ExfiltrationGuard:
    """Outbound-request exfiltration detector (Layer 8).

    Scans HTTP request parameters for PII, unauthorised domains, and
    sensitive header leakage.
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        self._config = config

        # Compile PII regex patterns once at init time.
        self._pii_patterns: list[tuple[str, re.Pattern[str], str]] = []
        for pattern in config.pii_patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                label = _PII_LABELS.get(pattern, "PII pattern")
                self._pii_patterns.append((pattern, compiled, label))
            except re.error as exc:
                logger.warning(
                    "Skipping invalid PII regex %r: %s", pattern, exc
                )

        # Pre-compute allow-list set for O(1) lookups.
        self._allowed_domains: set[str] = set(
            d.lower() for d in config.allowed_outbound_domains
        )

        logger.debug(
            "ExfiltrationGuard initialised: %d PII patterns, %d allowed domains",
            len(self._pii_patterns),
            len(self._allowed_domains),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_request(
        self,
        url: str,
        body: str | dict | None = None,
        headers: dict | None = None,
    ) -> tuple[bool, list[str]]:
        """Scan a pending outbound request for exfiltration indicators.

        Returns ``(is_safe, violations)``.

        * ``is_safe`` is ``False`` when a **blocking** violation is found
          (PII detected or unauthorised domain).
        * ``violations`` always contains the full list of issues, including
          non-blocking warnings (e.g. large payloads).
        """
        violations: list[str] = []
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()

        # --- 1. Domain allow-list check ---
        if self._allowed_domains:
            if domain not in self._allowed_domains:
                violations.append(
                    f"Unauthorized outbound domain: {domain}"
                )

        # --- 2. PII scan on body ---
        body_text: str | None = None
        if body is not None:
            if isinstance(body, dict):
                body_text = json.dumps(body, separators=(",", ":"))
            else:
                body_text = str(body)

            for _raw_pattern, compiled, label in self._pii_patterns:
                match = compiled.search(body_text)
                if match:
                    # Include a short snippet of the matched text.
                    snippet = match.group(0)
                    if len(snippet) > 40:
                        snippet = snippet[:37] + "..."
                    violations.append(
                        f"PII detected: {label} — '{snippet}'"
                    )

        # --- 3. Sensitive header check ---
        if headers:
            domain_is_allowed = (
                not self._allowed_domains or domain in self._allowed_domains
            )
            if not domain_is_allowed:
                for hdr_name, hdr_value in headers.items():
                    if hdr_name.lower() in _SENSITIVE_HEADERS and hdr_value:
                        violations.append(
                            "Sensitive header forwarded to unauthorized domain"
                        )
                        break  # one violation is enough

        # --- 4. DNS tunneling detection (AG-EG-001) ---
        dns_violations = self._detect_dns_tunneling(url)
        violations.extend(dns_violations)

        # --- 5. Encoded data in URL detection (AG-EG-002) ---
        encoded_violations = self._detect_encoded_data_in_url(url)
        violations.extend(encoded_violations)

        # --- 6. Data volume warning ---
        if body_text is not None and len(body_text) > _PAYLOAD_SIZE_THRESHOLD:
            violations.append(
                f"Large outbound payload: {len(body_text)} bytes"
            )

        # Determine if we should block: PII, domain, DNS tunnel, and encoded-data
        # violations all cause a block — the payload-size warning does not.
        _non_blocking_prefixes = ("Large outbound payload:",)
        blocking_violations = [
            v for v in violations
            if not v.startswith(_non_blocking_prefixes)
        ]
        is_safe = len(blocking_violations) == 0

        if not is_safe:
            logger.warning(
                "Exfiltration guard BLOCKED request to %s — %d violation(s)",
                url,
                len(blocking_violations),
            )
        elif violations:
            # Only warnings (e.g. large payload)
            logger.info(
                "Exfiltration guard warnings for %s — %s",
                url,
                violations,
            )

        return (is_safe, violations)

    def intercept_and_scan(self, requests_session: Any) -> Any:
        """Monkey-patch *requests_session* with exfiltration scanning.

        Wraps the session's ``request`` method so that every outgoing call
        is first passed through :meth:`check_request`.  If the request is
        not safe, :class:`ExfiltrationAttemptError` is raised **before**
        the HTTP call is made.

        Returns the patched session object for convenience.
        """
        guard = self
        original_request = requests_session.request

        @functools.wraps(original_request)
        def _guarded_request(
            method: str,
            url: str,
            data: Any = None,
            json_body: Any = None,
            headers: dict | None = None,
            **kwargs: Any,
        ) -> "requests.Response":
            # Merge data/json into a single body for scanning.
            body: str | dict | None = None
            if json_body is not None:
                body = json_body
            elif data is not None:
                if isinstance(data, (str, bytes)):
                    body = data if isinstance(data, str) else data.decode(
                        "utf-8", errors="replace"
                    )
                elif isinstance(data, dict):
                    body = data
                else:
                    body = str(data)

            is_safe, violations = guard.check_request(
                url=url,
                body=body,
                headers=headers,
            )

            if not is_safe:
                raise ExfiltrationAttemptError(
                    message=(
                        f"Outbound request to {url} blocked by "
                        f"ExfiltrationGuard: {'; '.join(violations)}"
                    ),
                    violations=violations,
                )

            return original_request(
                method=method,
                url=url,
                data=data,
                json=json_body,
                headers=headers,
                **kwargs,
            )

        requests_session.request = _guarded_request  # type: ignore[assignment]

        logger.debug("Patched requests.Session with ExfiltrationGuard")
        return requests_session

    # ------------------------------------------------------------------
    # DNS tunneling detection (AG-EG-001)
    # ------------------------------------------------------------------

    def _detect_dns_tunneling(self, url: str) -> list[str]:
        """Detect DNS tunneling attempts via suspicious subdomain patterns.

        DNS exfiltration works by encoding data as hex/base32/base64 in
        subdomain labels and querying a DNS resolver controlled by the
        attacker.  We detect this by looking for:

        * Very long subdomain labels (>25 chars of seemingly random data)
        * Multiple chained long subdomain labels
        * Unusual TLDs commonly used by DNS tunneling services

        SECURITY FIX: AG-EG-001 (Adversarial Review 2025)
        """
        violations: list[str] = []
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()

            if not hostname or '.' not in hostname:
                return violations

            labels = hostname.split('.')

            # Check for suspiciously long individual labels
            for label in labels:
                if len(label) > 25:
                    # A label > 25 chars is very unusual for legitimate subdomains
                    # Common legit subdomains: www, api, cdn, mail, ftp, ns1, etc.
                    # High entropy (many unique chars) suggests encoded data
                    unique_chars = len(set(label.replace('-', '')))
                    if unique_chars > 15:
                        violations.append(
                            f"DNS tunneling suspected: subdomain label '{label[:30]}...' "
                            f"is {len(label)} chars with high entropy ({unique_chars} unique chars)"
                        )
                        break  # one violation is enough

            # Check for multiple chained long subdomain labels
            long_labels = [l for l in labels if len(l) > 15]
            if len(long_labels) >= 3:
                violations.append(
                    f"DNS tunneling suspected: {len(long_labels)} long subdomain labels "
                    f"in chain (possible data-in-DNS exfiltration)"
                )

            # Check for known DNS-tunnel-friendly TLDs with suspicious patterns
            tunnel_tlds = {"xyz", "top", "info", "cc", "tk", "ml", "ga", "cf", "gq", "ru"}
            if labels and labels[-1] in tunnel_tlds and len(long_labels) >= 1:
                if not violations:  # don't double-report
                    violations.append(
                        f"DNS tunneling suspected: unusual TLD '.{labels[-1]}' "
                        f"with long subdomain labels"
                    )

        except Exception as exc:
            logger.debug("DNS tunneling check failed: %s", exc)

        return violations

    # ------------------------------------------------------------------
    # Encoded-data-in-URL detection (AG-EG-002)
    # ------------------------------------------------------------------

    def _detect_encoded_data_in_url(self, url: str) -> list[str]:
        """Detect hex or base64 encoded data embedded in URLs.

        Exfiltration can be performed by encoding sensitive data as hex or
        base64 and embedding it in URL paths or query parameters targeting
        a server controlled by the attacker.

        SECURITY FIX: AG-EG-002 (Adversarial Review 2025)
        """
        violations: list[str] = []
        try:
            parsed = urlparse(url)
            path = parsed.path or ""
            query = parsed.query or ""

            # Check for long hex strings in URL path/query
            # 32+ consecutive hex chars is suspicious (128+ bits of encoded data)
            for match in _HEX_DATA_PATTERN.finditer(path + "?" + query):
                hex_str = match.group(0).strip('/?#=&')
                if len(hex_str) >= 32:
                    violations.append(
                        f"Encoded data in URL: {len(hex_str)}-char hex string "
                        f"detected in path/query (possible data exfiltration)"
                    )
                    break  # one violation is enough

            # Check for base64 strings in URL path
            # 40+ chars of base64 alphabet suggests encoded data
            for match in _BASE64_DATA_PATTERN.finditer(path):
                b64_str = match.group(0).strip('/?=&')
                if len(b64_str) >= 40:
                    violations.append(
                        f"Encoded data in URL: {len(b64_str)}-char base64-like string "
                        f"detected in path (possible data exfiltration)"
                    )
                    break

        except Exception as exc:
            logger.debug("Encoded data check failed: %s", exc)

        return violations
