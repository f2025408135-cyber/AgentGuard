"""
AgentGuard - Open-source defense framework against AI Agent Traps.

Based on the taxonomy from:
Franklin, M., Tomašev, N., Jacobs, J., Leibo, J.Z., & Osindero, S. (2026).
AI Agent Traps. SSRN. https://doi.org/10.2139/ssrn.6372438
"""

__version__ = "0.1.0"
__author__ = "AgentGuard Contributors"

from agentguard.pipeline import AgentGuard
from agentguard.models import (
    TrustTier,
    TrapClass,
    DetectionSignal,
    TrustReport,
    MemoryEntry,
    AgentMessage,
    ActionRequest,
    GuardedResponse,
)
from agentguard.config import AgentGuardConfig
from agentguard.exceptions import (
    AgentGuardError,
    AgentGuardBlockedError,
    ExfiltrationAttemptError,
    TrustValidationError,
)
from agentguard.integrations import (
    GuardedWebBrowser,
    GuardedToolResultWrapper,
    GuardedToolExecutor,
)

__all__ = [
    "AgentGuard",
    "AgentGuardConfig",
    "TrustTier",
    "TrapClass",
    "DetectionSignal",
    "TrustReport",
    "MemoryEntry",
    "AgentMessage",
    "ActionRequest",
    "GuardedResponse",
    "AgentGuardError",
    "AgentGuardBlockedError",
    "ExfiltrationAttemptError",
    "TrustValidationError",
    "GuardedWebBrowser",
    "GuardedToolResultWrapper",
    "GuardedToolExecutor",
    "__version__",
]
