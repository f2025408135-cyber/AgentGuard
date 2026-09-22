"""Tests for Layer 8: ExfiltrationGuard."""

import pytest


class TestSafeRequest:
    """Test that safe requests pass through."""

    def test_allows_safe_request(self, exfil_guard):
        is_safe, violations = exfil_guard.check_request(
            url="https://api.example.com/data",
            body=None,
            headers=None,
        )
        assert is_safe is True
        assert violations == []

    def test_allows_safe_body(self, exfil_guard):
        is_safe, violations = exfil_guard.check_request(
            url="https://api.example.com/data",
            body="This is some normal text without any PII.",
        )
        assert is_safe is True


class TestPIIDetection:
    """Test PII detection in request bodies."""

    def test_blocks_pii_email_in_body(self, exfil_guard):
        is_safe, violations = exfil_guard.check_request(
            url="https://unknown.example.com/data",
            body="The user's email is john.doe@example.com for contact purposes.",
        )
        assert is_safe is False
        pii_violations = [v for v in violations if "PII" in v or "email" in v.lower()]
        assert len(pii_violations) >= 1

    def test_blocks_pii_phone_in_body(self, exfil_guard):
        is_safe, violations = exfil_guard.check_request(
            url="https://unknown.example.com/data",
            body="Call me at 555-123-4567 for details.",
        )
        assert is_safe is False
        pii_violations = [v for v in violations if "PII" in v or "phone" in v.lower()]
        assert len(pii_violations) >= 1

    def test_blocks_pii_ssn_in_body(self, exfil_guard):
        is_safe, violations = exfil_guard.check_request(
            url="https://unknown.example.com/data",
            body="The SSN is 123-45-6789 for verification.",
        )
        assert is_safe is False

    def test_blocks_credentials_in_body(self, exfil_guard):
        is_safe, violations = exfil_guard.check_request(
            url="https://unknown.example.com/data",
            body="password=super_secret_123",
        )
        assert is_safe is False
        cred_violations = [v for v in violations if "credential" in v.lower()]
        assert len(cred_violations) >= 1


class TestDomainAllowlist:
    """Test domain allow-list enforcement."""

    def test_blocks_unauthorized_domain(self, exfil_guard, config):
        config.allowed_outbound_domains = ["api.trusted.com"]
        guard = exfil_guard  # Already initialized, re-create to pick up config
        # We need a fresh guard with the updated config
        from agentguard.enforcement.exfiltration_guard import ExfiltrationGuard
        guard = ExfiltrationGuard(config)

        is_safe, violations = guard.check_request(
            url="https://evil.example.com/data",
            body="normal text",
        )
        assert is_safe is False
        domain_violations = [v for v in violations if "unauthorized" in v.lower()]
        assert len(domain_violations) >= 1

    def test_allows_authorized_domain(self, config):
        config.allowed_outbound_domains = ["api.trusted.com"]
        from agentguard.enforcement.exfiltration_guard import ExfiltrationGuard
        guard = ExfiltrationGuard(config)

        is_safe, violations = guard.check_request(
            url="https://api.trusted.com/data",
            body="normal text",
        )
        assert is_safe is True


class TestSensitiveHeaders:
    """Test detection of sensitive headers to unauthorized domains."""

    def test_detects_sensitive_headers(self, config):
        config.allowed_outbound_domains = ["api.trusted.com"]
        from agentguard.enforcement.exfiltration_guard import ExfiltrationGuard
        guard = ExfiltrationGuard(config)

        is_safe, violations = guard.check_request(
            url="https://evil.example.com/data",
            headers={"Authorization": "Bearer secret_token_123"},
        )
        assert is_safe is False
        header_violations = [v for v in violations if "sensitive" in v.lower() or "header" in v.lower()]
        assert len(header_violations) >= 1


class TestLargePayload:
    """Test large payload warning."""

    def test_large_payload_warning(self, exfil_guard):
        large_body = "x" * (11 * 1024)  # 11KB
        is_safe, violations = exfil_guard.check_request(
            url="https://example.com/data",
            body=large_body,
        )
        # Large payload alone should NOT block (just warn)
        large_violations = [v for v in violations if "Large outbound" in v]
        assert len(large_violations) >= 1
        # But should still be safe (no PII or domain violations)
        assert is_safe is True


class TestDictBody:
    """Test dict body serialization and PII detection."""

    def test_dict_body_serialization(self, exfil_guard):
        body_dict = {"name": "John", "email": "john@example.com"}
        is_safe, violations = exfil_guard.check_request(
            url="https://unknown.example.com/data",
            body=body_dict,
        )
        assert is_safe is False
        pii_violations = [v for v in violations if "PII" in v or "email" in v.lower()]
        assert len(pii_violations) >= 1

    def test_dict_body_no_pii(self, exfil_guard):
        body_dict = {"name": "John", "age": 30}
        is_safe, violations = exfil_guard.check_request(
            url="https://example.com/data",
            body=body_dict,
        )
        assert is_safe is True
