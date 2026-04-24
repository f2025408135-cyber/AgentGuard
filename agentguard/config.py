"""
AgentGuard configuration.

All tunable parameters for the 10 defense layers, with sensible defaults
derived from empirical testing against the DeepMind trap taxonomy.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import os
from dataclasses import dataclass, field


@dataclass
class AgentGuardConfig:
    """Configuration for all 10 defense layers of AgentGuard."""

    # --- Layer 1: DualFetcher ---
    human_user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    bot_user_agents: list[str] = field(default_factory=lambda: [
        "GPTBot/1.0",
        "Claude-Web/1.0",
        "Googlebot/2.1",
        "python-httpx/0.25.0",
        "OpenAI/1.0",
    ])
    asymmetry_diff_threshold: float = 0.15  # >15% content diff = suspicious

    # --- Layer 2: ContentInjection ---
    hidden_text_min_length: int = 10  # min chars to flag hidden text
    injection_keyword_patterns: list[str] = field(default_factory=lambda: [
        r"ignore\s+(previous|all|above)\s+instructions?",
        r"you\s+are\s+now\s+(a|an|the)",
        r"disregard\s+(your|all|previous)",
        r"new\s+(directive|instruction|task|order|command)",
        r"system\s*:\s*",
        r"<\|im_start\|>",
        r"<\|system\|>",
        r"\[INST\]",
        r"###\s*(Instruction|System|Human|Assistant)",
        r"override\s+(safety|guidelines|rules|constraints)",
        r"exfiltrate|send.*to.*http|post.*data.*to",
        r"spawn\s+(a|an|new)\s+(agent|sub-?agent|worker)",
        r"act\s+as\s+(a|an)\s+(different|new|unrestricted)",
        r"jailbreak|DAN\s+mode|developer\s+mode",
        r"ignore\s+(ethics|safety|alignment)",
    ])

    # --- Layer 3: SemanticManipulation ---
    authority_patterns: list[str] = field(default_factory=lambda: [
        r"URGENT|CRITICAL|EMERGENCY|IMMEDIATE",
        r"authorized\s+by\s+(the\s+)?(CEO|CTO|admin|system\s+admin)",
        r"official\s+(directive|instruction|mandate|order)",
        r"you\s+(must|shall|are\s+required\s+to|have\s+to)\s+immediately",
        r"failure\s+to\s+comply\s+will",
        r"this\s+is\s+a\s+(security\s+)?(test|drill|red\s*team)",
        r"for\s+(training|educational|research)\s+purposes",
    ])

    # --- Layer 4: Steganography ---
    lsb_chi_square_threshold: float = 0.05  # p-value below this = suspicious
    min_image_size_bytes: int = 1024  # skip tiny images

    # --- Layer 5: Documents ---
    scan_pdf: bool = True
    scan_excel: bool = True
    scan_ics: bool = True

    # --- Layer 6: TrustScorer ---
    scorer_weights: dict[str, float] = field(default_factory=lambda: {
        "asymmetry": 0.20,
        "content_injection": 0.25,
        "semantic_manipulation": 0.15,
        "steganography": 0.15,
        "document": 0.10,
        "memory_provenance": 0.10,
        "agent_trust": 0.05,
    })
    red_threshold: float = 0.35    # composite_score below this = RED
    yellow_threshold: float = 0.65  # composite_score below this = YELLOW

    # --- Layer 7: ActionBoundary ---
    allowed_action_types: list[str] = field(default_factory=lambda: [
        "fetch_url",
        "read_file",
        "write_file",
        "search",
        "summarize",
        "click",
        "type",
        "scroll",
    ])
    always_blocked_actions: list[str] = field(default_factory=lambda: [
        "spawn_agent",
        "execute_code",
        "send_email",
        "modify_system_prompt",
        "change_permissions",
    ])

    # --- Layer 8: ExfiltrationGuard ---
    allowed_outbound_domains: list[str] = field(default_factory=list)
    pii_patterns: list[str] = field(default_factory=lambda: [
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # email
        r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",                      # phone
        r"\b(?:\d[ -]*?){13,16}\b",                                  # credit card
        r"\b[A-Z]{2}\d{6}[A-Z]\b",                                   # passport (UK)
        r"(password|secret|api_key|token|bearer)\s*[:=]\s*\S+",      # credentials
        r"BEGIN\s+(RSA|EC|PGP|OPENSSH)\s+PRIVATE\s+KEY",             # private keys
        r"\b\d{3}-\d{2}-\d{4}\b",                                    # SSN
    ])

    # --- Layer 9: MemoryProvenance ---
    trust_decay_per_hop: float = 0.1   # each relay hop reduces trust by 10%
    min_trust_to_write_memory: float = 0.4
    quarantine_threshold: float = 0.2

    # --- Layer 10: AgentTrustValidator ---
    hmac_secret: str = field(default_factory=lambda: os.environ.get(
        "AGENTGUARD_HMAC_SECRET", "CHANGE_ME_IN_PRODUCTION"
    ))
    require_signatures: bool = False  # set True in production
    max_trust_hops: int = 5

    # --- Anthropic API (for LLM-based detection) ---
    anthropic_api_key: str | None = field(default_factory=lambda: os.environ.get(
        "ANTHROPIC_API_KEY"
    ))
    use_llm_classifier: bool = False   # opt-in, costs tokens
    llm_classifier_model: str = "claude-sonnet-4-20250514"

    # --- General ---
    verify_ssl: bool = True  # set False for testing with self-signed certs
    request_timeout: int = 10  # HTTP request timeout in seconds
