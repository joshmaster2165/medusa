"""Tests for the AI comprehensive analysis check."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from medusa.ai.client import configure_ai, reset_ai
from medusa.checks.ai_analysis.ai001_comprehensive_analysis import (
    AiComprehensiveAnalysisCheck,
)
from medusa.core.check import ServerSnapshot
from medusa.core.models import Status


@pytest.fixture
def snapshot() -> ServerSnapshot:
    return ServerSnapshot(
        server_name="test-server",
        transport_type="http",
        transport_url="http://localhost:3000",
        tools=[
            {
                "name": "read_file",
                "description": "Read a file from disk",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                    },
                },
            }
        ],
        resources=[],
        prompts=[],
        capabilities={},
        protocol_version="2025-03-26",
        server_info={"name": "test-mcp"},
    )


@pytest.fixture(autouse=True)
def _reset():
    reset_ai()
    yield
    reset_ai()


class TestAiComprehensiveAnalysisCheck:
    def test_metadata_loads(self):
        """Check metadata loads from YAML sidecar."""
        check = AiComprehensiveAnalysisCheck()
        meta = check.metadata()
        assert meta.check_id == "ai001"
        assert meta.category == "ai_analysis"
        assert "AI" in meta.title

    @pytest.mark.asyncio
    async def test_execute_returns_error_when_not_configured(
        self, snapshot
    ):
        """When AI isn't configured, check returns ERROR finding."""
        check = AiComprehensiveAnalysisCheck()
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.ERROR
        assert "not configured" in findings[0].status_extended.lower()

    @pytest.mark.asyncio
    async def test_execute_pass_when_no_issues(self, snapshot):
        """AI finds no issues → single PASS finding."""
        mock_client = MagicMock()
        mock_client.analyze = AsyncMock(
            return_value={"findings": []}
        )
        mock_credit_mgr = MagicMock()
        mock_credit_mgr.deduct = AsyncMock(return_value=True)

        configure_ai(
            client=mock_client, credit_manager=mock_credit_mgr
        )

        check = AiComprehensiveAnalysisCheck()
        findings = await check.execute(snapshot)

        assert len(findings) == 1
        assert findings[0].status == Status.PASS
        assert findings[0].check_id == "ai001"

    @pytest.mark.asyncio
    async def test_execute_fail_findings(self, snapshot):
        """AI detects issues → FAIL findings."""
        mock_client = MagicMock()
        mock_client.analyze = AsyncMock(
            return_value={
                "findings": [
                    {
                        "resource_type": "tool",
                        "resource_name": "read_file",
                        "severity": "high",
                        "title": "Path Traversal Risk",
                        "status_extended": "Tool reads arbitrary files",
                        "evidence": "No path validation",
                        "remediation": "Add path allowlist",
                        "owasp_mcp": ["MCP05:2025"],
                    }
                ]
            }
        )
        mock_credit_mgr = MagicMock()
        mock_credit_mgr.deduct = AsyncMock(return_value=True)

        configure_ai(
            client=mock_client, credit_manager=mock_credit_mgr
        )

        check = AiComprehensiveAnalysisCheck()
        findings = await check.execute(snapshot)

        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert findings[0].resource_name == "read_file"
        assert "[AI]" in findings[0].check_title

    @pytest.mark.asyncio
    async def test_execute_skipped_on_insufficient_credits(
        self, snapshot
    ):
        """No credits → SKIPPED finding."""
        mock_client = MagicMock()
        mock_credit_mgr = MagicMock()
        mock_credit_mgr.deduct = AsyncMock(return_value=False)

        configure_ai(
            client=mock_client, credit_manager=mock_credit_mgr
        )

        check = AiComprehensiveAnalysisCheck()
        findings = await check.execute(snapshot)

        assert len(findings) == 1
        assert findings[0].status == Status.SKIPPED
        assert "credits" in findings[0].status_extended.lower()

    @pytest.mark.asyncio
    async def test_execute_error_on_api_failure(self, snapshot):
        """Claude API error → ERROR finding."""
        mock_client = MagicMock()
        mock_client.analyze = AsyncMock(
            side_effect=Exception("API timeout")
        )
        mock_credit_mgr = MagicMock()
        mock_credit_mgr.deduct = AsyncMock(return_value=True)

        configure_ai(
            client=mock_client, credit_manager=mock_credit_mgr
        )

        check = AiComprehensiveAnalysisCheck()
        findings = await check.execute(snapshot)

        assert len(findings) == 1
        assert findings[0].status == Status.ERROR
        assert "API timeout" in findings[0].status_extended
