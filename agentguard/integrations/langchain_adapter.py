"""LangChain integration: drop-in GuardedWebBrowser tool.

Provides a wrapper that scans URLs through AgentGuard before returning
content to LangChain agents.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import logging
from typing import Optional, Type

from agentguard.exceptions import AgentGuardBlockedError

logger = logging.getLogger(__name__)

try:
    from langchain.tools import BaseTool
    from langchain.callbacks.manager import CallbackManagerForToolRun
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    BaseTool = object  # type: ignore


class GuardedWebBrowser:
    """
    Drop-in replacement for LangChain browser tools.
    Wraps any URL fetch through AgentGuard before returning to agent.

    Usage:
        from agentguard.integrations.langchain_adapter import GuardedWebBrowser
        from agentguard import AgentGuard

        browser = GuardedWebBrowser(guard=AgentGuard())
        content = browser.fetch("https://example.com")
        # Returns sanitized content or raises AgentGuardBlockedError
    """

    def __init__(self, guard):
        """Initialize with an AgentGuard instance.

        Args:
            guard: An AgentGuard instance for scanning.
        """
        self.guard = guard

    def fetch(self, url: str) -> str:
        """Fetch and scan a URL, returning sanitized content.

        Args:
            url: The URL to fetch and scan.

        Returns:
            Sanitized content string safe for agent consumption.

        Raises:
            AgentGuardBlockedError: If the URL is blocked by AgentGuard.
        """
        response = self.guard.scan_url(url)
        if response.blocked:
            raise AgentGuardBlockedError(
                f"AgentGuard blocked {url}: {response.block_reason}"
            )
        if response.warnings:
            warning_text = "\n".join(
                f"[AGENTGUARD WARNING: {w}]" for w in response.warnings
            )
            return f"{warning_text}\n\n{response.content}"
        return response.content or ""

    def fetch_with_report(self, url: str):
        """Fetch URL and return both content and trust report.

        Args:
            url: URL to fetch and scan.

        Returns:
            Tuple of (content: str, trust_report: TrustReport).
        """
        response = self.guard.scan_url(url)
        return (response.content or "", response.trust_report)


if LANGCHAIN_AVAILABLE:
    class GuardedWebBrowserTool(BaseTool):
        """LangChain BaseTool implementation of GuardedWebBrowser."""
        name: str = "guarded_web_browser"
        description: str = (
            "Fetches a web page through AgentGuard security scanning. "
            "Returns sanitized content with trust assessment. "
            "Blocked content is rejected before reaching the agent."
        )
        guard: object = None  # AgentGuard instance

        def _run(
            self,
            url: str,
            run_manager: Optional[CallbackManagerForToolRun] = None,
        ) -> str:
            """Execute the tool."""
            browser = GuardedWebBrowser(guard=self.guard)
            return browser.fetch(url)
