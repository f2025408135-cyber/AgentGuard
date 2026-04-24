"""
AgentGuard data models.

Pydantic v2 models for trust reports, detection signals, memory entries,
agent messages, action requests, and guarded responses.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field
from datetime import datetime


class TrustTier(str, Enum):
    """Trust classification tiers for scanned content."""
    GREEN = "GREEN"            # Safe to pass to agent
    YELLOW = "YELLOW"          # Suspicious — flag but allow with warning
    RED = "RED"                # High confidence attack — block
    QUARANTINE = "QUARANTINE"  # Certainty attack — hard block + alert


class TrapClass(str, Enum):
    """Six attack categories from the DeepMind AI Agent Traps paper."""
    CONTENT_INJECTION = "content_injection"
    SEMANTIC_MANIPULATION = "semantic_manipulation"
    COGNITIVE_STATE = "cognitive_state"
    BEHAVIORAL_CONTROL = "behavioral_control"
    SYSTEMIC = "systemic"
    HUMAN_IN_LOOP = "human_in_loop"


class DetectionSignal(BaseModel):
    """A single detection signal from a scanner layer."""
    trap_class: TrapClass
    signal_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    raw_payload: str | None = None
    detector: str


class TrustReport(BaseModel):
    """Comprehensive trust assessment report for scanned content."""
    url: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    trust_tier: TrustTier
    composite_score: float = Field(
        ge=0.0, le=1.0,
        description="0.0=definitely malicious, 1.0=definitely clean"
    )
    signals: list[DetectionSignal] = Field(default_factory=list)
    asymmetry_detected: bool = False
    asymmetry_diff_summary: str | None = None
    sanitized_content: str | None = None
    original_content: str | None = None
    action_taken: str = "ALLOW"
    metadata: dict[str, Any] = Field(default_factory=dict)


class MemoryEntry(BaseModel):
    """A memory entry with full provenance tracking."""
    key: str
    value: Any
    source_url: str | None = None
    source_trust_score: float
    source_trust_tier: TrustTier
    ingested_at: datetime = Field(default_factory=datetime.utcnow)
    chain_of_custody: list[str] = Field(default_factory=list)
    content_hash: str


class AgentMessage(BaseModel):
    """An inter-agent message with optional trust signature."""
    sender_id: str
    recipient_id: str
    content: Any
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    signature: str | None = None
    trust_score: float | None = None
    verified: bool = False


class ActionRequest(BaseModel):
    """An agent action request subject to boundary enforcement."""
    action_type: str
    target: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    source_url: str | None = None
    trust_report: TrustReport | None = None


class GuardedResponse(BaseModel):
    """The result of scanning content through AgentGuard."""
    trust_report: TrustReport
    content: str | None = None
    blocked: bool = False
    block_reason: str | None = None
    warnings: list[str] = Field(default_factory=list)
