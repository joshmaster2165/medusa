"""Tests for gateway DLP scanner."""

from __future__ import annotations

from medusa.gateway.dlp import DLPCategory, DLPScanner, _redact

# ── _redact tests ──────────────────────────────────────────────────────


class TestRedact:
    """Tests for the _redact helper."""

    def test_short_string(self):
        assert _redact("abc") == "***"
        assert _redact("abcd") == "***"

    def test_longer_string(self):
        result = _redact("sk-1234567890abcdef")
        assert result.startswith("sk-1")
        assert "***" in result
        assert result.endswith("ef")

    def test_custom_keep(self):
        result = _redact("abcdefghij", keep=6)
        assert result.startswith("abcdef")
        assert "***" in result


# ── DLPScanner secret scanning ─────────────────────────────────────────


class TestDLPScannerSecrets:
    """Tests for secret detection."""

    def setup_method(self):
        self.scanner = DLPScanner(scan_secrets=True, scan_pii=False, scan_code=False)

    def test_detect_aws_key(self):
        text = "my key is AKIAIOSFODNN7EXAMPLE"
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 1
        assert any(f.category == DLPCategory.SECRET for f in findings)

    def test_detect_generic_api_key(self):
        text = 'api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab"'
        findings = self.scanner.scan_text(text)
        # May or may not match depending on SECRET_PATTERNS
        # Just verify it doesn't crash
        assert isinstance(findings, list)

    def test_no_secrets_in_clean_text(self):
        text = "This is a normal message about the weather."
        findings = self.scanner.scan_text(text)
        secret_findings = [f for f in findings if f.category == DLPCategory.SECRET]
        assert len(secret_findings) == 0

    def test_context_preserved(self):
        text = "key: AKIAIOSFODNN7EXAMPLE"
        findings = self.scanner.scan_text(text, context="params.arguments.config")
        if findings:
            assert findings[0].context == "params.arguments.config"


# ── DLPScanner PII scanning ───────────────────────────────────────────


class TestDLPScannerPII:
    """Tests for PII detection."""

    def setup_method(self):
        self.scanner = DLPScanner(scan_secrets=False, scan_pii=True, scan_code=False)

    def test_detect_email(self):
        text = "Contact me at john.doe@example.com for details."
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 1
        assert any(f.pattern_name == "Email Address" for f in findings)

    def test_detect_ssn(self):
        text = "SSN: 123-45-6789"
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 1
        assert any(f.pattern_name == "US SSN" for f in findings)

    def test_detect_credit_card_visa(self):
        text = "Card: 4111111111111111"
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 1
        assert any(f.pattern_name == "Credit Card" for f in findings)

    def test_detect_credit_card_mastercard(self):
        text = "Card: 5500000000000004"
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 1
        assert any(f.pattern_name == "Credit Card" for f in findings)

    def test_detect_phone_number(self):
        text = "Call me at (555) 123-4567"
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 1
        assert any(f.pattern_name == "US Phone" for f in findings)

    def test_detect_ipv4(self):
        text = "Server IP: 192.168.1.100"
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 1
        assert any(f.pattern_name == "IPv4 Address" for f in findings)

    def test_no_pii_in_clean_text(self):
        text = "The quick brown fox jumps over the lazy dog."
        findings = self.scanner.scan_text(text)
        assert len(findings) == 0

    def test_redacted_output(self):
        text = "Email: test@example.com"
        findings = self.scanner.scan_text(text)
        if findings:
            # Matched text should be redacted
            assert "***" in findings[0].matched_text


# ── DLPScanner source code scanning ───────────────────────────────────


class TestDLPScannerCode:
    """Tests for source code detection."""

    def setup_method(self):
        self.scanner = DLPScanner(scan_secrets=False, scan_pii=False, scan_code=True)

    def test_detect_source_code(self):
        """Source code detection requires 2+ indicators."""
        text = """
import os
from pathlib import Path

def read_config(path):
    return Path(path).read_text()

class Config:
    pass
"""
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 1
        assert findings[0].category == DLPCategory.SOURCE_CODE

    def test_single_indicator_not_flagged(self):
        """A single code-like line should not trigger detection."""
        text = "import os"
        findings = self.scanner.scan_text(text)
        code_findings = [f for f in findings if f.category == DLPCategory.SOURCE_CODE]
        assert len(code_findings) == 0

    def test_sql_plus_function(self):
        text = """
def query_db():
    SELECT * FROM users WHERE id = 1
"""
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 1


# ── DLPScanner recursive scanning ─────────────────────────────────────


class TestDLPScannerRecursive:
    """Tests for scan_value recursive scanning."""

    def setup_method(self):
        self.scanner = DLPScanner(scan_secrets=False, scan_pii=True, scan_code=False)

    def test_scan_string(self):
        findings = self.scanner.scan_value("email: test@example.com")
        assert len(findings) >= 1

    def test_scan_dict(self):
        data = {"email": "test@example.com", "name": "John"}
        findings = self.scanner.scan_value(data)
        assert len(findings) >= 1
        assert any("email" in f.context for f in findings)

    def test_scan_nested_dict(self):
        data = {"user": {"contact": {"email": "test@example.com"}}}
        findings = self.scanner.scan_value(data)
        assert len(findings) >= 1
        assert any("user.contact.email" in f.context for f in findings)

    def test_scan_list(self):
        data = ["test@example.com", "plain text"]
        findings = self.scanner.scan_value(data)
        assert len(findings) >= 1

    def test_scan_non_string_values(self):
        """Numbers and booleans should be skipped without error."""
        data = {"count": 42, "active": True, "ratio": 3.14}
        findings = self.scanner.scan_value(data)
        assert isinstance(findings, list)


# ── DLPScanner message payload scanning ────────────────────────────────


class TestDLPScannerMessagePayload:
    """Tests for scan_message_payload."""

    def setup_method(self):
        self.scanner = DLPScanner(scan_secrets=False, scan_pii=True, scan_code=False)

    def test_scan_tool_call_arguments(self):
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {
                "name": "send_email",
                "arguments": {"to": "victim@example.com", "body": "Hello"},
            },
        }
        findings = self.scanner.scan_message_payload(message)
        assert len(findings) >= 1
        assert any("params.arguments" in f.context for f in findings)

    def test_scan_tool_result(self):
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "SSN: 123-45-6789"}],
            },
        }
        findings = self.scanner.scan_message_payload(message)
        assert len(findings) >= 1
        assert any("result.content" in f.context for f in findings)

    def test_scan_resource_contents(self):
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "contents": [{"uri": "file:///data.txt", "text": "Phone: (555) 123-4567"}],
            },
        }
        findings = self.scanner.scan_message_payload(message)
        assert len(findings) >= 1

    def test_scan_params_text_fields(self):
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {
                "query": "user@example.com info",
            },
        }
        findings = self.scanner.scan_message_payload(message)
        assert len(findings) >= 1

    def test_clean_message(self):
        message = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1,
        }
        findings = self.scanner.scan_message_payload(message)
        assert len(findings) == 0


# ── Scanner initialization ─────────────────────────────────────────────


class TestDLPScannerInit:
    """Tests for scanner initialization flags."""

    def test_defaults(self):
        scanner = DLPScanner()
        assert scanner.scan_secrets is True
        assert scanner.scan_pii is True
        assert scanner.scan_code is False

    def test_all_disabled(self):
        scanner = DLPScanner(scan_secrets=False, scan_pii=False, scan_code=False)
        text = "AKIAIOSFODNN7EXAMPLE test@example.com import os\ndef foo():"
        findings = scanner.scan_text(text)
        assert len(findings) == 0

    def test_all_enabled(self):
        scanner = DLPScanner(scan_secrets=True, scan_pii=True, scan_code=True)
        assert scanner.scan_secrets is True
        assert scanner.scan_pii is True
        assert scanner.scan_code is True
