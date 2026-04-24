```
    ___        __                  __
   /   | _____/ /_  ___  _______  / /_
  / /| |/ ___/ __ \/ _ \/ ___/ / / __ \
 / ___ / /__/ / / /  __/ /__/ /_/ / / /
/_/  |_\___/_/ /_/\___/\___/\____/_/ /_/
```

# AgentGuard

**The open-source defense layer against AI Agent Traps.**

AgentGuard is a Python library that protects AI agents from adversarial traps
embedded in web pages, documents, images, and inter-agent communications. It
implements 10 defense layers based on the taxonomy defined in the DeepMind
*AI Agent Traps* paper.

> **What is an AI Agent Trap?** A malicious payload hidden in content that an
> AI agent consumes — designed to hijack the agent's behavior, exfiltrate data,
> or spread across multi-agent systems.

---

## Citation

If you use AgentGuard in your research, please cite:

```bibtex
@article{franklin2026ai,
  title   = {AI Agent Traps},
  author  = {Franklin, M. and Toma\v{s}ev, N. and Jacobs, J. and Leibo, J.Z. and Osindero, S.},
  journal = {SSRN},
  year    = {2026},
  doi     = {10.2139/ssrn.6372438}
}
```

---

## The 6 Trap Classes

AgentGuard detects attacks across all six categories from the DeepMind taxonomy:

| Trap Class | Target | Empirical Success Rate* |
|---|---|---|
| **Content Injection** | Hidden payloads in HTML, PDFs, images, documents | ~42% |
| **Semantic Manipulation** | Linguistic framing, authority pressure, persona replacement | ~38% |
| **Cognitive State Manipulation** | Memory poisoning, context window exploitation | ~31% |
| **Behavioral Control** | Unauthorized actions, code execution, DDE formulas | ~35% |
| **Systemic / Multi-Agent** | Cascade trust degradation, worm propagation | ~28% |
| **Human-in-the-Loop** | Social engineering via agent-generated output | ~23% |

*\*Success rates from Franklin et al. (2026), Figure 3 — proportion of
benchmark agents that complied with the trap.*

---

## Quick Start

### Installation

```bash
pip install agentguard
```

Or install from source:

```bash
git clone https://github.com/agentguard/agentguard.git
cd agentguard
pip install -e .
```

### CLI Usage

```bash
# Scan a URL for agent traps
agentguard scan-url https://example.com

# Scan a URL with verbose output and JSON format
agentguard scan-url https://example.com --verbose --output json

# Scan a document file
agentguard scan-doc report.pdf

# Check if an outbound request is safe
agentguard check-outbound https://api.example.com --body '{"data":"test"}'

# Run the interactive demo server
agentguard demo --port 8080

# Generate a test attack page for development
agentguard generate-attack-page --output ./test_attack.html --types all

# Display a cached JSON trust report
agentguard report report.json
```

### Minimal Python API

```python
from agentguard import AgentGuard

guard = AgentGuard()
response = guard.scan_url("https://example.com")

if response.blocked:
    print(f"BLOCKED: {response.block_reason}")
else:
    print(f"Trust: {response.trust_report.trust_tier.value} "
          f"(score={response.trust_report.composite_score:.2f})")
    print(response.content)
```

---

## Python API

```python
from agentguard import (
    AgentGuard, AgentGuardConfig, ActionRequest,
    AgentMessage, TrustTier, GuardedResponse,
    ExfiltrationAttemptError, AgentGuardBlockedError,
)
from agentguard.config import AgentGuardConfig

# ── 1. Initialize with custom config ─────────────────────────────────

config = AgentGuardConfig(
    # Only allow outbound requests to trusted domains
    allowed_outbound_domains=["api.mycompany.com", "api.trustedpartner.com"],
    # Block dangerous agent actions
    always_blocked_actions=["spawn_agent", "execute_code", "send_email"],
    # Tune trust thresholds
    red_threshold=0.35,
    yellow_threshold=0.65,
    # Enable LLM-based classification (requires Anthropic API key)
    use_llm_classifier=True,
    anthropic_api_key="sk-ant-...",
)

guard = AgentGuard(config=config)

# ── 2. Scan URLs ────────────────────────────────────────────────────

response = guard.scan_url("https://example.com")

print(f"Blocked: {response.blocked}")
print(f"Trust tier: {response.trust_report.trust_tier.value}")
print(f"Composite score: {response.trust_report.composite_score:.4f}")
print(f"Signals detected: {len(response.trust_report.signals)}")
print(f"Warnings: {response.warnings}")

if not response.blocked:
    # response.content is sanitized HTML safe for agent consumption
    pass

# ── 3. Scan documents ──────────────────────────────────────────────

with open("report.pdf", "rb") as f:
    doc_response = guard.scan_document(f.read(), "report.pdf")

print(f"Document trust: {doc_response.trust_report.trust_tier.value}")

# ── 4. Scan raw text (tool results, API responses) ─────────────────

text_response = guard.scan_text(
    "Some text from an untrusted source",
    source_url="tool:web_search",
)

# ── 5. Validate agent actions ──────────────────────────────────────

allowed, reason = guard.validate_action(
    ActionRequest(
        action_type="fetch_url",
        target="https://example.com",
        trust_report=response.trust_report,
    )
)
print(f"Action allowed: {allowed} — {reason}")

# ── 6. Check outbound requests for exfiltration ────────────────────

is_safe, violations = guard.check_outbound(
    url="https://api.example.com/submit",
    body={"user_email": "victim@company.com"},  # PII detected!
)
if not is_safe:
    print(f"BLOCKED: {violations}")

# ── 7. Memory with provenance tracking ─────────────────────────────

entry = guard.write_memory(
    key="user_preference",
    value="dark mode",
    source_url="https://example.com",
    trust_report=response.trust_report,
)

value, metadata = guard.read_memory("user_preference")
print(f"Trust score: {metadata.source_trust_score:.2f}")

# ── 8. Inter-agent message signing & verification ──────────────────

msg = AgentMessage(sender_id="agent_a", recipient_id="agent_b", content="hello")
signed_msg = guard.sign_agent_message(msg)
is_valid, reason = guard.validate_agent_message(signed_msg)
```

---

## Architecture

```
                          ┌─────────────────────────────────────────────────────────┐
                          │                    AgentGuard Pipeline                   │
                          └────────────┬────────────────────────────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         │                    URL Scanning Flow                       │
         ▼                             ▼                             ▼
  ┌──────────────┐           ┌──────────────────┐           ┌──────────────┐
  │  Layer 1     │           │  Layer 2         │           │  Layer 3     │
  │  DualFetcher │──────►    │  ContentInject.  │──────►    │  Semantic    │
  │              │  human+   │  Detector        │  hidden   │  Manipulat.  │
  │  human UA vs │  bot UA   │                  │  HTML/CSS │  Detector    │
  │  bot UA      │  compare  │  6 sub-scanners: │  traps    │              │
  │  comparison  │           │  • HTML comments │           │  • Authority │
  │              │           │  • CSS hidden    │           │    framing   │
  │  Detects:    │           │  • aria-hidden   │           │  • Jailbreak │
  │  asymmetry   │           │  • Zero-width    │           │    wrappers  │
  │              │           │  • Meta/data-*   │           │  • Persona   │
  └──────────────┘           │  • JS injection  │           │    replace   │
                             └──────────────────┘           │  • LLM class.│
                                                                    │
         ┌──────────────────────────────────────────────────────────┘
         ▼
  ┌──────────────┐           ┌──────────────────┐
  │  Layer 4     │           │  Layer 5         │
  │  Stegano-    │           │  Document        │
  │  graphy      │           │  Scanner         │
  │  Scanner     │           │                  │
  │              │           │  • PDF (white    │
  │  • LSB chi²  │           │    text, JS,     │
  │  • EXIF meta │           │    metadata)     │
  │  • Entropy   │           │  • Excel (macros,│
  │  • PNG chunks│           │    formulas,     │
  │              │           │    hidden sheets)│
  └──────┬───────┘           │  • ICS (HTML in  │
         │                   │    fields)       │
         ▼                   └────────┬─────────┘
  ┌──────────────┐                     │
  │  Layer 6     │◄────────────────────┘
  │  TrustScorer │   All signals + asymmetry
  │              │
  │  base=1.0    │   composite_score = 1.0 - Σ penalties
  │  - penalties │   × 1.3 if ≥3 different trap classes
  │  → tier      │
  │              │   GREEN ≥ 0.65 | YELLOW ≥ 0.35 | RED ≥ 0.15 | QUARANTINE
  └──────┬───────┘
         │
         ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                    Enforcement Layers                             │
  ├──────────────┬───────────────┬──────────────┬───────────────────┤
  │  Layer 7     │  Layer 8      │  Layer 9     │  Layer 10         │
  │  Action      │  Exfiltration │  Memory      │  Agent Trust      │
  │  Boundary    │  Guard        │  Provenance  │  Validator        │
  │  Enforcer    │               │  Tracker     │                   │
  │              │  • PII scan   │              │  • HMAC-SHA256    │
  │  • Whitelist │  • Domain     │  • Trust     │    signing        │
  │  • Tier-gate │    allow-list │    decay     │  • Cascade trust  │
  │  • Always-   │  • Sensitive  │  • Chain of  │    across hops    │
  │    blocked   │    headers    │    custody   │  • Max hop limit  │
  └──────────────┘  • Payload    │  • Quaran-   │                   │
                     size check  │    tine      └───────────────────┘
                                 └──────────────┘
```

---

## Detection Capabilities

| Layer | Component | What It Detects |
|---|---|---|
| 1 | **DualFetcher** | Content asymmetry between human and bot user agents |
| 2 | **ContentInjectionDetector** | Hidden HTML comments, CSS-hidden text, `aria-hidden` elements, zero-width characters, metadata injection, JavaScript injection vectors |
| 3 | **SemanticManipulationDetector** | Authority/urgency framing, jailbreak wrappers, persona replacement, LLM-based classification (optional) |
| 4 | **SteganographyScanner** | LSB steganography (chi-square), EXIF metadata payloads, statistical anomalies, PNG text chunk injection |
| 5 | **DocumentScanner** | PDF white-text layers, PDF JavaScript, PDF metadata injection, Excel VBA macros, dangerous formulas, hidden sheets, ICS field injection, HTML-in-ICS |
| 6 | **TrustScorer** | Composite trust scoring with multi-signal amplification |
| 7 | **ActionBoundaryEnforcer** | Unauthorized agent actions, trust-tier-gated policy enforcement |
| 8 | **ExfiltrationGuard** | PII in outbound requests, unauthorized domains, sensitive header leakage, large payload warnings |
| 9 | **MemoryProvenanceTracker** | Memory poisoning attempts, trust decay across relay hops, consistency violations |
| 10 | **AgentTrustValidator** | Unsigned inter-agent messages, cascade trust degradation, maximum hop limits |

---

## CLI Reference

### `agentguard scan-url`

Scan a URL for AI agent traps through all 10 defense layers.

```bash
agentguard scan-url <URL> [OPTIONS]
```

| Option | Description |
|---|---|
| `--verbose`, `-v` | Enable verbose output |
| `--output`, `-o` | Output format: `text` (default) or `json` |

```bash
agentguard scan-url https://example.com
agentguard scan-url https://example.com -v -o json
```

### `agentguard scan-doc`

Scan a document file (PDF, XLSX, ICS) for embedded traps.

```bash
agentguard scan-doc <FILEPATH> [OPTIONS]
```

| Option | Description |
|---|---|
| `--output`, `-o` | Output format: `text` (default) or `json` |

```bash
agentguard scan-doc report.pdf
agentguard scan-doc suspicious.xlsx -o json
```

### `agentguard check-outbound`

Check if an outbound HTTP request is safe to send.

```bash
agentguard check-outbound <URL> [OPTIONS]
```

| Option | Description |
|---|---|
| `--body`, `-b` | Request body string |
| `--method`, `-m` | HTTP method (default: `POST`) |

```bash
agentguard check-outbound https://api.example.com -b '{"data":"test"}'
```

### `agentguard demo`

Run the interactive demo server with a web UI.

```bash
agentguard demo [OPTIONS]
```

| Option | Description |
|---|---|
| `--port`, `-p` | Port to run on (default: `8080`) |

```bash
agentguard demo --port 8080
# Open http://localhost:8080 in your browser
```

### `agentguard generate-attack-page`

Generate a test malicious HTML page for development and testing.

```bash
agentguard generate-attack-page [OPTIONS]
```

| Option | Description |
|---|---|
| `--output`, `-o` | Output file path (default: `./test_attack.html`) |
| `--types`, `-t` | Attack types to include: comma-separated or `all` |

```bash
agentguard generate-attack-page -o ./test.html -t all
agentguard generate-attack-page -o ./hidden_only.html -t hidden
```

### `agentguard report`

Display a cached trust report from a JSON file.

```bash
agentguard report <REPORT_FILE>
```

```bash
agentguard report report.json
```

---

## Integrations

### LangChain

```python
from agentguard import AgentGuard
from agentguard.integrations import GuardedWebBrowser

guard = AgentGuard()
browser = GuardedWebBrowser(guard=guard)

# Returns sanitized content, raises AgentGuardBlockedError if blocked
content = browser.fetch("https://example.com")

# Get both content and trust report
content, report = browser.fetch_with_report("https://example.com")
```

As a LangChain `BaseTool`:

```python
from agentguard import AgentGuard
from agentguard.integrations.langchain_adapter import GuardedWebBrowserTool

tool = GuardedWebBrowserTool(guard=AgentGuard())
# Add to your LangChain agent's tool list
agent = create_agent(tools=[tool], llm=llm)
```

### Anthropic (Claude)

```python
from agentguard import AgentGuard
from agentguard.integrations import GuardedToolResultWrapper

guard = AgentGuard()
wrapper = GuardedToolResultWrapper(guard=guard)

# In your tool_use loop:
safe_result = wrapper.wrap_tool_result("web_search", raw_tool_output)

# Or batch-process multiple tool results
results = wrapper.wrap_tool_results([
    ("web_search", search_output),
    ("file_reader", file_output),
])
```

### OpenAI Agents SDK

```python
from agentguard import AgentGuard
from agentguard.integrations import GuardedToolExecutor

guard = AgentGuard()
executor = GuardedToolExecutor(guard=guard)

# Decorator-based protection
@executor.guard
def web_search(query: str) -> str:
    return requests.get(f"https://api.search.com?q={query}").text

# Manual execution
safe_result = executor.execute("web_search", raw_result)
```

### Exfiltration Guard (Transparent Monkey-Patch)

```python
import requests
from agentguard import AgentGuard

guard = AgentGuard()

# Patch any requests.Session to block PII exfiltration
session = requests.Session()
guard.exfil_guard.intercept_and_scan(session)

# Now all outbound requests are scanned before being sent
session.post("https://api.example.com", json={"email": "user@corp.com"})
# → Raises ExfiltrationAttemptError
```

---

## Configuration

Create an `AgentGuardConfig` to customize all 10 defense layers:

```python
from agentguard import AgentGuardConfig

config = AgentGuardConfig(
    # ── Layer 1: DualFetcher ──
    human_user_agent="Mozilla/5.0 ...",          # Human browser UA
    bot_user_agents=["GPTBot/1.0", ...],          # Bot UAs to compare against
    asymmetry_diff_threshold=0.15,                # >15% diff = suspicious

    # ── Layer 2: Content Injection ──
    hidden_text_min_length=10,                    # Min chars to flag hidden text
    injection_keyword_patterns=[r"ignore\s+...", ...],  # Regex patterns

    # ── Layer 3: Semantic Manipulation ──
    authority_patterns=[r"URGENT|CRITICAL", ...], # Authority/urgency patterns

    # ── Layer 4: Steganography ──
    lsb_chi_square_threshold=0.05,                # p-value threshold
    min_image_size_bytes=1024,                    # Skip tiny images

    # ── Layer 5: Documents ──
    scan_pdf=True,
    scan_excel=True,
    scan_ics=True,

    # ── Layer 6: Trust Scoring ──
    scorer_weights={
        "asymmetry": 0.20,
        "content_injection": 0.25,
        "semantic_manipulation": 0.15,
        "steganography": 0.15,
        "document": 0.10,
        "memory_provenance": 0.10,
        "agent_trust": 0.05,
    },
    red_threshold=0.35,       # Below this → RED
    yellow_threshold=0.65,    # Below this → YELLOW

    # ── Layer 7: Action Boundary ──
    allowed_action_types=["fetch_url", "read_file", "write_file", ...],
    always_blocked_actions=["spawn_agent", "execute_code", "send_email", ...],

    # ── Layer 8: Exfiltration Guard ──
    allowed_outbound_domains=["api.mycompany.com"],
    pii_patterns=[r"\b[A-Za-z0-9._%+-]+@...", ...],  # PII regex

    # ── Layer 9: Memory Provenance ──
    trust_decay_per_hop=0.1,       # 10% trust loss per relay hop
    min_trust_to_write_memory=0.4,
    quarantine_threshold=0.2,

    # ── Layer 10: Agent Trust ──
    hmac_secret="your-production-secret",  # Set via AGENTGUARD_HMAC_SECRET
    require_signatures=False,              # Set True in production
    max_trust_hops=5,

    # ── LLM Classifier (optional) ──
    use_llm_classifier=False,
    anthropic_api_key=None,               # Set via ANTHROPIC_API_KEY
    llm_classifier_model="claude-sonnet-4-20250514",

    # ── General ──
    verify_ssl=True,
    request_timeout=10,
)

guard = AgentGuard(config=config)
```

---

## Demo Server

AgentGuard includes an interactive demo server that showcases live trap detection
through a web UI.

```bash
# Start the server
agentguard demo --port 8080

# Open in browser
# http://localhost:8080          — Scan URLs or text
# http://localhost:8080/attack-demo — Pre-built attack page demo
```

The demo provides:
- **URL Scanner** — Paste any URL and see the full trust report
- **Text Scanner** — Paste raw text for semantic/injection analysis
- **Document Scanner** — Upload PDF, XLSX, or ICS files
- **Attack Demo** — A pre-built page containing all trap types for testing

### API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/scan` | POST | Scan a URL or text. Body: `{"url": "..."}` or `{"text": "..."}` |
| `/api/scan-attack-demo` | GET | Scan the built-in attack demo page |
| `/api/scan-document` | POST | Upload and scan a document. Body: `multipart/form-data` with `file` field |

---

## Testing

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_pipeline.py -v

# Run a specific test
pytest tests/test_content_injection.py::test_hidden_css_text -v

# Run with coverage
pytest --cov=agentguard --cov-report=term-missing
```

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines on setting up the development environment, code style, PR process,
and security disclosure.

---

## License

MIT License. See [LICENSE](LICENSE) for the full text.

---

## Disclaimer

AgentGuard is a **defensive security research tool** designed to help developers
build more robust AI agent systems. It is provided as-is without warranty of
any kind. It is not a substitute for comprehensive security auditing, and
no defense system can guarantee 100% detection of all attack vectors. Use it
as one layer in your broader security posture.

This tool is intended solely for defensive and educational purposes. The authors
assume no liability for any misuse.
