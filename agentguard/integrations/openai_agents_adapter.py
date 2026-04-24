"""OpenAI Agents SDK integration: GuardedToolExecutor.

Provides a wrapper for OpenAI function calling / tool execution
that scans results through AgentGuard before returning to the model.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import logging
import json
from typing import Any, Callable

logger = logging.getLogger(__name__)


class GuardedToolExecutor:
    """
    Wraps OpenAI agent tool execution with AgentGuard scanning.

    Usage:
        executor = GuardedToolExecutor(guard=AgentGuard())

        # Wrap a tool function
        @executor.guard
        def web_search(query: str) -> str:
            return requests.get(f"https://api.search.com?q={query}").text

        # Or wrap manually
        safe_result = executor.execute("web_search", raw_result)
    """

    def __init__(self, guard):
        """Initialize with an AgentGuard instance.

        Args:
            guard: An AgentGuard instance.
        """
        self._guard = guard
        self._original_functions: dict[str, Callable] = {}

    def execute(self, tool_name: str, raw_result: str) -> str:
        """Scan a tool result before returning it to the agent.

        Args:
            tool_name: Name of the tool that produced the result.
            raw_result: Raw result string from the tool.

        Returns:
            Sanitized result string.
        """
        response = self._guard.scan_text(
            raw_result, source_url=f"tool:{tool_name}"
        )
        if response.blocked:
            logger.warning(
                "AgentGuard blocked tool result from '%s': %s",
                tool_name, response.block_reason,
            )
            return (
                f"[AGENTGUARD BLOCKED: Tool '{tool_name}' returned content "
                f"that failed security scanning. Trust score: "
                f"{response.trust_report.composite_score:.2f}. "
                f"Do not use this data.]"
            )
        return response.content or raw_result

    def guard(self, func: Callable) -> Callable:
        """Decorator to wrap a tool function with AgentGuard scanning.

        Args:
            func: The tool function to wrap.

        Returns:
            Wrapped function that scans output through AgentGuard.
        """
        func_name = func.__name__
        self._original_functions[func_name] = func

        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            return self.execute(func_name, str(result))

        wrapper.__name__ = func_name
        wrapper.__doc__ = func.__doc__
        return wrapper
