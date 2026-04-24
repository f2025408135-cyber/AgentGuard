"""AgentGuard custom exceptions."""


class AgentGuardError(Exception):
    """Base exception for all AgentGuard errors."""
    pass


class AgentGuardBlockedError(AgentGuardError):
    """Raised when AgentGuard blocks a request due to detected threats."""
    def __init__(self, message: str, trust_report: dict | None = None):
        super().__init__(message)
        self.trust_report = trust_report


class ExfiltrationAttemptError(AgentGuardError):
    """Raised when an exfiltration attempt is detected and blocked."""
    def __init__(self, message: str, violations: list[str] | None = None):
        super().__init__(message)
        self.violations = violations or []


class TrustValidationError(AgentGuardError):
    """Raised when an inter-agent message fails trust validation."""
    pass


class ConfigurationError(AgentGuardError):
    """Raised when AgentGuard is misconfigured."""
    pass


class FetchError(AgentGuardError):
    """Raised when a URL fetch fails."""
    pass


class ScanError(AgentGuardError):
    """Raised when scanning a document or content fails."""
    pass


class QuarantineError(AgentGuardError):
    """Raised when attempting to use quarantined content."""
    pass
