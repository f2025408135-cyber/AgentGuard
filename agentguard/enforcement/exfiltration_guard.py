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

        # --- 4. Data volume warning ---
        if body_text is not None and len(body_text) > _PAYLOAD_SIZE_THRESHOLD:
            violations.append(
                f"Large outbound payload: {len(body_text)} bytes"
            )

        # Determine if we should block: only PII and domain violations
        # cause a block — the payload-size warning does not.
        blocking_violations = [
            v for v in violations
            if not v.startswith("Large outbound payload:")
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
