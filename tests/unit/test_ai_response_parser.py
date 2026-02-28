"""Tests for medusa.ai.response_parser — Claude response → Finding conversion."""

from __future__ import annotations

import pytest

from medusa.ai.response_parser import parse_ai_response
from medusa.core.models import CheckMetadata, Severity, Status


@pytest.fixture
def sample_meta() -> CheckMetadata:
    return CheckMetadata(
        check_id="ai001",
        title="[AI] Comprehensive Security Analysis",
        category="ai_analysis",
        severity=Severity.HIGH,
        description="AI-powered analysis",
        risk_explanation="Deep semantic analysis",
        remediation="Review findings",
        owasp_mcp=["MCP01:2025"],
    )


class TestParseAiResponse:
    def test_empty_findings_returns_pass(self, sample_meta):
        """Empty findings array → single PASS finding."""
        result = parse_ai_response(
            response={"findings": []},
            meta=sample_meta,
            server_name="test-server",
            server_transport="http",
        )
        assert len(result) == 1
        assert result[0].status == Status.PASS
        assert result[0].check_id == "ai001"

    def test_single_finding(self, sample_meta):
        """A single AI finding is parsed correctly."""
        response = {
            "findings": [
                {
                    "resource_type": "tool",
                    "resource_name": "exec_cmd",
                    "severity": "critical",
                    "title": "Arbitrary Code Execution",
                    "status_extended": "Tool allows arbitrary code",
                    "evidence": "description says 'execute any command'",
                    "remediation": "Restrict to safe commands",
                    "owasp_mcp": ["MCP02:2025"],
                }
            ]
        }
        result = parse_ai_response(
            response=response,
            meta=sample_meta,
            server_name="srv",
            server_transport="stdio",
        )
        assert len(result) == 1
        f = result[0]
        assert f.status == Status.FAIL
        assert f.severity == Severity.CRITICAL
        assert f.resource_type == "tool"
        assert f.resource_name == "exec_cmd"
        assert "[AI]" in f.check_title
        assert f.evidence == "description says 'execute any command'"

    def test_multiple_findings(self, sample_meta):
        """Multiple findings are all parsed."""
        response = {
            "findings": [
                {
                    "resource_type": "tool",
                    "resource_name": "t1",
                    "severity": "high",
                    "title": "Issue 1",
                    "status_extended": "Problem 1",
                },
                {
                    "resource_type": "prompt",
                    "resource_name": "p1",
                    "severity": "medium",
                    "title": "Issue 2",
                    "status_extended": "Problem 2",
                },
            ]
        }
        result = parse_ai_response(
            response=response,
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
        )
        assert len(result) == 2
        assert result[0].severity == Severity.HIGH
        assert result[1].severity == Severity.MEDIUM

    def test_missing_findings_key_returns_error(self, sample_meta):
        """Response without 'findings' key → ERROR finding."""
        result = parse_ai_response(
            response={"issues": []},
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
        )
        assert len(result) == 1
        assert result[0].status == Status.ERROR

    def test_findings_not_a_list_returns_error(self, sample_meta):
        """findings: 'string' → ERROR finding."""
        result = parse_ai_response(
            response={"findings": "not a list"},
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
        )
        assert len(result) == 1
        assert result[0].status == Status.ERROR

    def test_unknown_severity_defaults_to_medium(self, sample_meta):
        """Unknown severity string defaults to MEDIUM."""
        response = {
            "findings": [
                {
                    "resource_type": "tool",
                    "resource_name": "t",
                    "severity": "extreme",
                    "title": "Test",
                    "status_extended": "Test issue",
                }
            ]
        }
        result = parse_ai_response(
            response=response,
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
        )
        assert result[0].severity == Severity.MEDIUM

    def test_invalid_resource_type_defaults_to_server(self, sample_meta):
        """Unknown resource_type defaults to 'server'."""
        response = {
            "findings": [
                {
                    "resource_type": "widget",
                    "resource_name": "x",
                    "severity": "low",
                    "title": "Test",
                    "status_extended": "Test",
                }
            ]
        }
        result = parse_ai_response(
            response=response,
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
        )
        assert result[0].resource_type == "server"

    def test_missing_optional_fields_use_defaults(self, sample_meta):
        """Findings with only required fields still parse."""
        response = {
            "findings": [
                {
                    "status_extended": "Minimal finding",
                }
            ]
        }
        result = parse_ai_response(
            response=response,
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
        )
        assert len(result) == 1
        assert result[0].status == Status.FAIL
        assert result[0].resource_name == "srv"

    def test_non_dict_finding_skipped(self, sample_meta):
        """Non-dict items in findings array are skipped."""
        response = {
            "findings": [
                "not a dict",
                {
                    "resource_type": "tool",
                    "resource_name": "t",
                    "severity": "low",
                    "title": "Real",
                    "status_extended": "Real finding",
                },
            ]
        }
        result = parse_ai_response(
            response=response,
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
        )
        # The string is skipped, only the dict is parsed
        assert len(result) == 1
        assert result[0].resource_name == "t"
