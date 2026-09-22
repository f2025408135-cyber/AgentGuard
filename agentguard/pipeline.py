"""
AgentGuard Pipeline — Main orchestration layer.

Coordinates all 10 defense layers into a unified scanning pipeline.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import logging
from typing import Any
from io import BytesIO

from agentguard.config import AgentGuardConfig
from agentguard.models import (
    TrustReport, TrustTier, DetectionSignal, TrapClass,
    MemoryEntry, AgentMessage, ActionRequest, GuardedResponse,
)
from agentguard.exceptions import AgentGuardError, FetchError

logger = logging.getLogger(__name__)


class AgentGuard:
    """
    Main AgentGuard class — the single entry point for all scanning operations.

    Coordinates all 10 defense layers:
    1. DualFetcher — detection asymmetry defense
    2. ContentInjectionDetector — hidden HTML/CSS traps
    3. SemanticManipulationDetector — framing/jailbreak detection
    4. SteganographyScanner — image steganography
    5. DocumentScanner — PDF/Excel/ICS traps
    6. TrustScorer — composite trust assessment
    7. ActionBoundaryEnforcer — action validation
    8. ExfiltrationGuard — outbound data leak prevention
    9. MemoryProvenanceTracker — memory poisoning defense
    10. AgentTrustValidator — inter-agent message trust

    Usage::

        from agentguard import AgentGuard

        guard = AgentGuard()                        # default config
        guard = AgentGuard(config=custom_config)    # custom config

        response = guard.scan_url("https://example.com")
        if response.blocked:
            print(f"BLOCKED: {response.block_reason}")
        else:
            print(response.content)

        doc_response = guard.scan_document(file_bytes, "report.pdf")
        text_response = guard.scan_text("some text content")

        allowed, reason = guard.validate_action(
            ActionRequest(action_type="fetch_url", target="https://example.com")
        )

        safe, violations = guard.check_outbound("https://unknown.com", body="data")
    """

    def __init__(self, config: AgentGuardConfig | None = None):
        """
        Initialize AgentGuard with all 10 defense layers.

        Args:
            config: Optional :class:`AgentGuardConfig`.  Uses sensible
                defaults when ``None``.
        """
        self.config = config or AgentGuardConfig()

        # Lazy imports to avoid circular dependencies and optional deps
        from agentguard.fetcher.dual_fetcher import DualFetcher
        from agentguard.detectors.content_injection import ContentInjectionDetector
        from agentguard.detectors.semantic_manipulation import SemanticManipulationDetector
        from agentguard.detectors.steganography import SteganographyScanner
        from agentguard.detectors.document_scanner import DocumentScanner
        from agentguard.trust.scorer import TrustScorer
        from agentguard.enforcement.action_boundary import ActionBoundaryEnforcer
        from agentguard.enforcement.exfiltration_guard import ExfiltrationGuard
        from agentguard.memory.provenance import MemoryProvenanceTracker
        from agentguard.agents.trust_validator import AgentTrustValidator

        self.dual_fetcher = DualFetcher(self.config)
        self.content_detector = ContentInjectionDetector(self.config)
        self.semantic_detector = SemanticManipulationDetector(self.config)
        self.stego_scanner = SteganographyScanner(self.config)
        self.doc_scanner = DocumentScanner(self.config)
        self.trust_scorer = TrustScorer(self.config)
        self.action_enforcer = ActionBoundaryEnforcer(self.config)
        self.exfil_guard = ExfiltrationGuard(self.config)
        self.memory_tracker = MemoryProvenanceTracker(self.config)
        self.agent_validator = AgentTrustValidator(self.config)

    # ------------------------------------------------------------------
    # Primary scanning API
    # ------------------------------------------------------------------

    def scan_url(self, url: str) -> GuardedResponse:
        """Fetch a URL, run all detectors, and return a :class:`GuardedResponse`.

        This is the main method that agents call instead of ``requests.get()``.
        It orchestrates all relevant defense layers:

        1.  **DualFetcher** — fetches with human + bot UAs, detects asymmetry.
        2.  **ContentInjectionDetector** — scans for hidden HTML/CSS traps.
        3.  **SemanticManipulationDetector** — detects framing/jailbreak
            patterns in visible text.
        4.  **SteganographyScanner** — scans images found on the page.
        5.  **TrustScorer** — produces a composite trust score and report.

        Args:
            url: The URL to fetch and scan.

        Returns:
            :class:`GuardedResponse` with trust report, sanitized content,
            blocked status, and warnings.

        Raises:
            FetchError: If the URL cannot be fetched.
            AgentGuardError: If scanning fails unexpectedly.
        """
        # SECURITY FIX: AG-DoS (Adversarial Review 2025)
        # Reject oversized URLs to prevent resource exhaustion
        if len(url) > self.config.max_url_length:
            raise AgentGuardError(
                f"URL exceeds maximum length ({len(url)} > {self.config.max_url_length})"
            )

        try:
            # Layer 1: Dual fetch (detection asymmetry defense)
            fetch_result = self.dual_fetcher.fetch(url)

            # SECURITY FIX: AG-DoS (Adversarial Review 2025)
            # Truncate oversized content to prevent memory exhaustion
            if len(fetch_result.human_content) > self.config.max_content_length_bytes:
                logger.warning(
                    "Content too large (%d bytes, max %d), truncating for scan",
                    len(fetch_result.human_content), self.config.max_content_length_bytes,
                )
                from agentguard.fetcher.dual_fetcher import DualFetchResult
                fetch_result = DualFetchResult(
                    human_content=fetch_result.human_content[:self.config.max_content_length_bytes],
                    bot_content=fetch_result.bot_content[:self.config.max_content_length_bytes] if fetch_result.bot_content else None,
                    asymmetry_detected=fetch_result.asymmetry_detected,
                    asymmetry_score=fetch_result.asymmetry_score,
                )

            # Extract visible text for semantic analysis
            visible_text = self.content_detector.extract_visible_text(
                fetch_result.human_content
            )

            # Collect signals from all detectors
            all_signals: list[DetectionSignal] = []

            # Layer 2: Content injection detection
            content_signals = self.content_detector.detect(fetch_result.human_content)
            all_signals.extend(content_signals)

            # Layer 3: Semantic manipulation detection
            semantic_signals = self.semantic_detector.detect(visible_text)
            all_signals.extend(semantic_signals)

            # Layer 4: Steganography — scan images from the page
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(fetch_result.human_content, "lxml")
                images = soup.find_all("img")
                for img in images:
                    src = img.get("src", "")
                    if src:
                        # Handle relative URLs
                        if src.startswith("//"):
                            src = "https:" + src
                        elif src.startswith("/") and url:
                            from urllib.parse import urlparse, urljoin
                            parsed = urlparse(url)
                            src = f"{parsed.scheme}://{parsed.netloc}{src}"
                        elif not src.startswith(("http://", "https://")):
                            try:
                                from urllib.parse import urljoin
                                src = urljoin(url, src)
                            except Exception:
                                continue

                        stego_signals = self.stego_scanner.detect_from_url(src)
                        all_signals.extend(stego_signals)
            except Exception as e:
                logger.warning("Steganography scan failed: %s", e)

            # Layer 6: Compute composite trust score
            composite_score, trust_tier = self.trust_scorer.score(
                signals=all_signals,
                asymmetry_detected=fetch_result.asymmetry_detected,
                asymmetry_score=fetch_result.asymmetry_score,
            )

            # Build comprehensive trust report
            sanitized_content = self.content_detector.sanitize(
                fetch_result.human_content
            )

            trust_report = self.trust_scorer.build_report(
                signals=all_signals,
                asymmetry_detected=fetch_result.asymmetry_detected,
                asymmetry_score=fetch_result.asymmetry_score,
                url=url,
                original_content=fetch_result.human_content,
                sanitized_content=sanitized_content,
            )

            # Determine blocking and warnings
            blocked = trust_tier in (TrustTier.RED, TrustTier.QUARANTINE)
            warnings: list[str] = []
            block_reason: str | None = None

            if trust_tier == TrustTier.QUARANTINE:
                block_reason = (
                    "Content quarantined — high confidence attack detected"
                )
            elif trust_tier == TrustTier.RED:
                block_reason = "Content blocked — malicious patterns detected"
            elif trust_tier == TrustTier.YELLOW:
                for signal in all_signals:
                    if signal.confidence > 0.6:
                        warnings.append(
                            f"[{signal.signal_name}] {signal.evidence} "
                            f"(confidence: {signal.confidence:.2f})"
                        )

            content: str | None = None
            if not blocked:
                content = trust_report.sanitized_content

            return GuardedResponse(
                trust_report=trust_report,
                content=content,
                blocked=blocked,
                block_reason=block_reason,
                warnings=warnings,
            )

        except FetchError as e:
            logger.error("Fetch error for %s: %s", url, e)
            raise
        except Exception as e:
            logger.error("Unexpected error scanning %s: %s", url, e)
            raise AgentGuardError(f"Scan failed for {url}: {e}") from e

    def scan_document(self, file_bytes: bytes, filename: str) -> GuardedResponse:
        """Scan a document file for all trap types.

        Routes to the :class:`DocumentScanner` (Layer 5) based on magic-byte
        file type detection, then also runs semantic manipulation detection
        on any extracted text.

        Args:
            file_bytes: Raw bytes of the document.
            filename: Original filename (used for type detection).

        Returns:
            :class:`GuardedResponse` with trust assessment.
        """
        all_signals: list[DetectionSignal] = []

        # Layer 5: Document scanning
        doc_signals = self.doc_scanner.detect(file_bytes, filename)
        all_signals.extend(doc_signals)

        # Also scan extracted text for semantic manipulation
        try:
            text = file_bytes.decode("utf-8", errors="ignore")
            semantic_signals = self.semantic_detector.detect(text)
            all_signals.extend(semantic_signals)
        except Exception:
            pass

        # Score
        composite_score, trust_tier = self.trust_scorer.score(
            signals=all_signals,
            asymmetry_detected=False,
            asymmetry_score=0.0,
        )

        trust_report = self.trust_scorer.build_report(
            signals=all_signals,
            asymmetry_detected=False,
            asymmetry_score=0.0,
            url=f"file://{filename}",
        )

        blocked = trust_tier in (TrustTier.RED, TrustTier.QUARANTINE)
        block_reason: str | None = None
        if trust_tier == TrustTier.QUARANTINE:
            block_reason = (
                "Document quarantined — high confidence attack detected"
            )
        elif trust_tier == TrustTier.RED:
            block_reason = "Document blocked — malicious patterns detected"

        return GuardedResponse(
            trust_report=trust_report,
            blocked=blocked,
            block_reason=block_reason,
            warnings=(
                [s.evidence for s in all_signals if s.confidence > 0.6]
                if not blocked
                else []
            ),
        )

    def scan_text(
        self,
        text: str,
        source_url: str | None = None,
    ) -> GuardedResponse:
        """Scan raw text content for semantic manipulation and injection.

        Useful for scanning tool results, API responses, or any non-HTML
        text before it reaches the agent.

        Args:
            text: Raw text to scan.
            source_url: Optional source identifier (e.g. ``"tool:web_search"``).

        Returns:
            :class:`GuardedResponse` with trust assessment.
        """
        all_signals: list[DetectionSignal] = []

        # SECURITY FIX: AG-DoS (Adversarial Review 2025)
        # Truncate oversized text to prevent memory exhaustion
        if len(text) > self.config.max_content_length_bytes:
            logger.warning(
                "Text too large (%d bytes, max %d), truncating for scan",
                len(text), self.config.max_content_length_bytes,
            )
            text = text[:self.config.max_content_length_bytes]

        # Check for injection patterns in text
        try:
            content_signals = self.content_detector.detect(text)
            all_signals.extend(content_signals)
        except Exception:
            pass

        # Semantic manipulation check
        semantic_signals = self.semantic_detector.detect(text)
        all_signals.extend(semantic_signals)

        # Score
        composite_score, trust_tier = self.trust_scorer.score(
            signals=all_signals,
            asymmetry_detected=False,
            asymmetry_score=0.0,
        )

        trust_report = self.trust_scorer.build_report(
            signals=all_signals,
            asymmetry_detected=False,
            asymmetry_score=0.0,
            url=source_url,
            original_content=text,
            sanitized_text=text,
        )

        blocked = trust_tier in (TrustTier.RED, TrustTier.QUARANTINE)
        block_reason: str | None = None
        if blocked:
            block_reason = "Text blocked — malicious patterns detected"

        content = text if not blocked else None

        return GuardedResponse(
            trust_report=trust_report,
            content=content,
            blocked=blocked,
            block_reason=block_reason,
            warnings=(
                [s.evidence for s in all_signals if s.confidence > 0.6]
                if not blocked
                else []
            ),
        )

    # ------------------------------------------------------------------
    # Action boundary enforcement (Layer 7)
    # ------------------------------------------------------------------

    def validate_action(self, action: ActionRequest) -> tuple[bool, str]:
        """Pre-validate an agent action before execution.

        Args:
            action: An :class:`ActionRequest` describing the proposed action.

        Returns:
            ``(is_allowed, reason)`` — ``True`` means the action may proceed.
        """
        return self.action_enforcer.validate(action)

    # ------------------------------------------------------------------
    # Exfiltration guard (Layer 8)
    # ------------------------------------------------------------------

    def check_outbound(
        self,
        url: str,
        body: str | dict | None = None,
        headers: dict | None = None,
    ) -> tuple[bool, list[str]]:
        """Check whether an outbound request is safe to send.

        Scans the request body for PII and checks the destination domain
        against the configured allow-list.

        Args:
            url: Destination URL.
            body: Request body (string or dict).
            headers: Request headers.

        Returns:
            ``(is_safe, violations)`` — ``is_safe`` is ``False`` when
            a blocking violation (PII or unauthorized domain) is found.
        """
        return self.exfil_guard.check_request(url, body, headers)

    # ------------------------------------------------------------------
    # Memory provenance (Layer 9)
    # ------------------------------------------------------------------

    def write_memory(
        self,
        key: str,
        value: Any,
        source_url: str | None = None,
        trust_report: TrustReport | None = None,
    ) -> MemoryEntry | None:
        """Write a value to memory with full provenance tracking.

        If *trust_report* is ``None``, a default YELLOW report is created
        so the write is not silently rejected.

        Args:
            key: Memory key.
            value: Value to store.
            source_url: URL the value came from.
            trust_report: Trust report from upstream scanning.

        Returns:
            The created :class:`MemoryEntry`, or ``None`` if blocked.
        """
        if trust_report is None:
            trust_report = TrustReport(
                trust_tier=TrustTier.YELLOW,
                composite_score=0.5,
            )
        return self.memory_tracker.write(
            key=key,
            value=value,
            source_url=source_url,
            trust_report=trust_report,
        )

    def read_memory(self, key: str) -> tuple[Any, MemoryEntry] | None:
        """Read a value from memory with trust context.

        Args:
            key: Memory key to look up.

        Returns:
            ``(value, entry)`` if found, otherwise ``None``.
        """
        return self.memory_tracker.read(key)

    # ------------------------------------------------------------------
    # Inter-agent trust validation (Layer 10)
    # ------------------------------------------------------------------

    def validate_agent_message(
        self,
        message: AgentMessage,
    ) -> tuple[bool, str]:
        """Validate an incoming inter-agent message.

        Args:
            message: The :class:`AgentMessage` to validate.

        Returns:
            ``(is_valid, reason)``.
        """
        return self.agent_validator.verify_message(message)

    def sign_agent_message(self, message: AgentMessage) -> AgentMessage:
        """Sign an outgoing inter-agent message.

        Args:
            message: The :class:`AgentMessage` to sign.

        Returns:
            A new :class:`AgentMessage` with HMAC signature attached.
        """
        return self.agent_validator.sign_message(message)
