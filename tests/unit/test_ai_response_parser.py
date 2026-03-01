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


class TestParseAiResponseCategoryAware:
    """Tests for category-aware mode (valid_check_ids provided)."""

    def test_valid_check_id_from_claude(self, sample_meta):
        """Claude returns a known static check_id -> used as-is."""
        response = {
            "findings": [
                {
                    "check_id": "tp001",
                    "resource_type": "tool",
                    "resource_name": "exec",
                    "severity": "critical",
                    "title": "[AI] Hidden Instructions",
                    "status_extended": "Found hidden content",
                    "owasp_mcp": ["MCP03:2025"],
                }
            ]
        }
        result = parse_ai_response(
            response=response,
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
            valid_check_ids={"tp001", "tp002", "tp003"},
        )
        assert len(result) == 1
        assert result[0].check_id == "tp001"
        assert result[0].check_title == "[AI] Hidden Instructions"

    def test_unknown_check_id_still_accepted(self, sample_meta):
        """Claude returns unknown check_id -> accepted with warning."""
        response = {
            "findings": [
                {
                    "check_id": "tp0ai",
                    "resource_type": "tool",
                    "resource_name": "x",
                    "severity": "high",
                    "title": "Novel Issue",
                    "status_extended": "New issue type",
                }
            ]
        }
        result = parse_ai_response(
            response=response,
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
            valid_check_ids={"tp001", "tp002"},
        )
        assert len(result) == 1
        assert result[0].check_id == "tp0ai"

    def test_missing_check_id_falls_back_to_meta(self, sample_meta):
        """Claude omits check_id -> falls back to AI check's ID."""
        response = {
            "findings": [
                {
                    "resource_type": "tool",
                    "resource_name": "x",
                    "severity": "medium",
                    "title": "Some Issue",
                    "status_extended": "Details",
                }
            ]
        }
        result = parse_ai_response(
            response=response,
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
            valid_check_ids={"tp001", "tp002"},
        )
        assert len(result) == 1
        assert result[0].check_id == "ai001"

    def test_legacy_mode_ignores_check_id_from_claude(self, sample_meta):
        """Without valid_check_ids, check_id always comes from meta."""
        response = {
            "findings": [
                {
                    "check_id": "tp001",
                    "resource_type": "tool",
                    "resource_name": "x",
                    "severity": "high",
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
            # No valid_check_ids -> legacy mode
        )
        assert len(result) == 1
        assert result[0].check_id == "ai001"  # From meta, not Claude

    def test_ai_prefix_added_when_missing(self, sample_meta):
        """Title without [AI] prefix gets it added."""
        response = {
            "findings": [
                {
                    "check_id": "tp001",
                    "resource_type": "tool",
                    "resource_name": "x",
                    "severity": "high",
                    "title": "No Prefix Here",
                    "status_extended": "Test",
                }
            ]
        }
        result = parse_ai_response(
            response=response,
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
            valid_check_ids={"tp001"},
        )
        assert result[0].check_title == "[AI] No Prefix Here"

    def test_ai_prefix_not_duplicated(self, sample_meta):
        """Title already with [AI] prefix doesn't get doubled."""
        response = {
            "findings": [
                {
                    "check_id": "tp001",
                    "resource_type": "tool",
                    "resource_name": "x",
                    "severity": "high",
                    "title": "[AI] Already Prefixed",
                    "status_extended": "Test",
                }
            ]
        }
        result = parse_ai_response(
            response=response,
            meta=sample_meta,
            server_name="srv",
            server_transport="http",
            valid_check_ids={"tp001"},
        )
        assert result[0].check_title == "[AI] Already Prefixed"
