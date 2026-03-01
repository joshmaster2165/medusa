"""Tests for the category-aware AI analysis checks."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from medusa.ai.client import configure_ai, reset_ai
from medusa.checks.ai_analysis._base import (
    BaseAiCategoryCheck,
    _first_sentence,
)
from medusa.checks.ai_analysis.ai001_tool_poisoning import (
    AiToolPoisoningCheck,
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
    from medusa.ai.throttle import reset_throttle

    reset_ai()
    reset_throttle()
    yield
    reset_ai()
    reset_throttle()


class TestBaseAiCategoryCheck:
    """Tests that apply to the shared BaseAiCategoryCheck base class."""

    def test_all_24_checks_load_metadata(self):
        """All 24 AI category checks load their metadata successfully."""
        from medusa.checks.ai_analysis import (
            ai001_tool_poisoning,
            ai002_authentication,
            ai003_input_validation,
            ai004_credential_exposure,
            ai005_privilege_scope,
            ai006_transport_security,
            ai007_data_protection,
            ai008_integrity,
            ai009_session_management,
            ai010_error_handling,
            ai011_rate_limiting,
            ai012_ssrf_network,
            ai013_agentic_behavior,
            ai014_sampling_security,
            ai015_context_security,
            ai016_resource_security,
            ai017_multi_tenant,
            ai018_secrets_management,
            ai019_server_hardening,
            ai020_governance,
            ai021_audit_logging,
            ai022_supply_chain,
            ai023_server_identity,
            ai024_prompt_security,
        )

        modules = [
            ai001_tool_poisoning,
            ai002_authentication,
            ai003_input_validation,
            ai004_credential_exposure,
            ai005_privilege_scope,
            ai006_transport_security,
            ai007_data_protection,
            ai008_integrity,
            ai009_session_management,
            ai010_error_handling,
            ai011_rate_limiting,
            ai012_ssrf_network,
            ai013_agentic_behavior,
            ai014_sampling_security,
            ai015_context_security,
            ai016_resource_security,
            ai017_multi_tenant,
            ai018_secrets_management,
            ai019_server_hardening,
            ai020_governance,
            ai021_audit_logging,
            ai022_supply_chain,
            ai023_server_identity,
            ai024_prompt_security,
        ]

        check_ids = set()
        for mod in modules:
            # Find the BaseAiCategoryCheck subclass in the module
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseAiCategoryCheck)
                    and attr is not BaseAiCategoryCheck
                ):
                    instance = attr()
                    meta = instance.metadata()
                    assert meta.check_id.startswith("ai")
                    assert meta.category == "ai_analysis"
                    assert "[AI]" in meta.title
                    check_ids.add(meta.check_id)

        assert len(check_ids) == 24

    def test_tool_poisoning_metadata(self):
        """ai001 (tool_poisoning) metadata is correct."""
        check = AiToolPoisoningCheck()
        meta = check.metadata()
        assert meta.check_id == "ai001"
        assert meta.category == "ai_analysis"
        assert "[AI]" in meta.title
        assert "MCP03:2025" in meta.owasp_mcp

    def test_category_returns_correct_value(self):
        """_category() returns the static category name."""
        check = AiToolPoisoningCheck()
        assert check._category() == "tool_poisoning"


class TestAiCategoryCheckExecution:
    """Tests for the execute() flow in BaseAiCategoryCheck."""

    @pytest.mark.asyncio
    async def test_execute_returns_error_when_not_configured(
        self, snapshot
    ):
        """When AI isn't configured, check returns ERROR finding."""
        check = AiToolPoisoningCheck()
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.ERROR
        assert "not configured" in findings[0].status_extended.lower()

    @pytest.mark.asyncio
    async def test_execute_pass_when_no_issues(self, snapshot):
        """AI finds no issues -> single PASS finding."""
        mock_client = MagicMock()
        mock_client.analyze = AsyncMock(
            return_value={"findings": []}
        )

        configure_ai(client=mock_client)

        check = AiToolPoisoningCheck()
        findings = await check.execute(snapshot)

        assert len(findings) == 1
        assert findings[0].status == Status.PASS
        assert findings[0].check_id == "ai001"

    @pytest.mark.asyncio
    async def test_execute_fail_findings_with_static_check_id(
        self, snapshot
    ):
        """AI detects issues -> FAIL findings with static check_ids."""
        mock_client = MagicMock()
        mock_client.analyze = AsyncMock(
            return_value={
                "findings": [
                    {
                        "check_id": "tp001",
                        "resource_type": "tool",
                        "resource_name": "read_file",
                        "severity": "critical",
                        "title": "[AI] Hidden Instructions",
                        "status_extended": "Hidden instructions found",
                        "evidence": "Base64 encoded text in description",
                        "remediation": "Remove hidden content",
                        "owasp_mcp": ["MCP03:2025"],
                    }
                ]
            }
        )

        configure_ai(client=mock_client)

        check = AiToolPoisoningCheck()
        findings = await check.execute(snapshot)

        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert findings[0].resource_name == "read_file"
        assert "[AI]" in findings[0].check_title
        # The check_id should be the static ID from Claude's response
        assert findings[0].check_id == "tp001"

    @pytest.mark.asyncio
    async def test_execute_error_on_api_failure(self, snapshot):
        """Claude API error -> ERROR finding."""
        mock_client = MagicMock()
        mock_client.analyze = AsyncMock(
            side_effect=Exception("API timeout")
        )

        configure_ai(client=mock_client)

        check = AiToolPoisoningCheck()
        findings = await check.execute(snapshot)

        assert len(findings) == 1
        assert findings[0].status == Status.ERROR
        assert "API timeout" in findings[0].status_extended

    @pytest.mark.asyncio
    async def test_execute_multiple_findings(self, snapshot):
        """AI returns multiple findings for different static checks."""
        mock_client = MagicMock()
        mock_client.analyze = AsyncMock(
            return_value={
                "findings": [
                    {
                        "check_id": "tp001",
                        "resource_type": "tool",
                        "resource_name": "read_file",
                        "severity": "critical",
                        "title": "[AI] Hidden Instructions",
                        "status_extended": "Hidden content found",
                        "evidence": "Base64 in description",
                        "remediation": "Remove hidden content",
                        "owasp_mcp": ["MCP03:2025"],
                    },
                    {
                        "check_id": "tp002",
                        "resource_type": "tool",
                        "resource_name": "read_file",
                        "severity": "high",
                        "title": "[AI] Prompt Injection",
                        "status_extended": "Injection found",
                        "evidence": "Suspicious wording",
                        "remediation": "Sanitize description",
                        "owasp_mcp": ["MCP06:2025"],
                    },
                ]
            }
        )

        configure_ai(client=mock_client)

        check = AiToolPoisoningCheck()
        findings = await check.execute(snapshot)

        assert len(findings) == 2
        assert findings[0].check_id == "tp001"
        assert findings[1].check_id == "tp002"
        assert all(f.status == Status.FAIL for f in findings)
        assert all("[AI]" in f.check_title for f in findings)

    @pytest.mark.asyncio
    async def test_no_per_check_credit_deduction(self, snapshot):
        """Credits are NOT deducted per-check (handled once at scan start)."""
        mock_client = MagicMock()
        mock_client.analyze = AsyncMock(
            return_value={"findings": []}
        )
        mock_credit_mgr = MagicMock()
        mock_credit_mgr.deduct = AsyncMock(return_value=True)

        configure_ai(
            client=mock_client, credit_manager=mock_credit_mgr
        )

        check = AiToolPoisoningCheck()
        await check.execute(snapshot)

        # Credit manager should NOT be called by individual checks
        mock_credit_mgr.deduct.assert_not_called()

    @pytest.mark.asyncio
    async def test_coverage_logging_low_coverage(
        self, snapshot, caplog
    ):
        """Low coverage triggers a warning log."""
        mock_client = MagicMock()
        mock_client.analyze = AsyncMock(
            return_value={
                "checks_evaluated": ["tp001", "tp002"],
                "findings": [],
            }
        )

        configure_ai(client=mock_client)

        check = AiToolPoisoningCheck()
        with caplog.at_level(logging.WARNING):
            await check.execute(snapshot)

        # tool_poisoning has 25 checks; 2/25 = 8% < 80% threshold
        assert any(
            "below 80%" in record.message
            for record in caplog.records
        )

    @pytest.mark.asyncio
    async def test_coverage_logging_good_coverage(
        self, snapshot, caplog
    ):
        """Good coverage doesn't trigger a warning."""
        # Build a complete checks_evaluated list
        check_obj = AiToolPoisoningCheck()
        valid_ids = check_obj._get_valid_check_ids()

        mock_client = MagicMock()
        mock_client.analyze = AsyncMock(
            return_value={
                "checks_evaluated": list(valid_ids),
                "findings": [],
            }
        )

        configure_ai(client=mock_client)

        with caplog.at_level(logging.WARNING):
            await check_obj.execute(snapshot)

        assert not any(
            "below 80%" in record.message
            for record in caplog.records
        )


class TestFirstSentence:
    """Tests for the _first_sentence helper."""

    def test_single_sentence(self):
        assert _first_sentence("Hello world.") == "Hello world."

    def test_multi_sentence(self):
        assert _first_sentence("First. Second.") == "First."

    def test_no_period(self):
        assert _first_sentence("No period here") == "No period here"

    def test_whitespace(self):
        result = _first_sentence("  First sentence. Second.  ")
        assert result == "First sentence."

    def test_newline_in_text(self):
        result = _first_sentence("First sentence.\nSecond line.")
        assert result == "First sentence."

    def test_long_text_without_period(self):
        long = "x" * 300
        result = _first_sentence(long)
        assert len(result) == 200


class TestBuildCheckList:
    """Tests for the _build_check_list method."""

    def test_includes_category_header(self):
        check = AiToolPoisoningCheck()
        check_list = check._build_check_list()
        assert "CHECKS IN CATEGORY 'tool_poisoning'" in check_list
        assert "evaluate ALL" in check_list

    def test_includes_what_and_look_for(self):
        check = AiToolPoisoningCheck()
        check_list = check._build_check_list()
        assert "What:" in check_list
        # At least some checks should have "Look for:"
        assert "Look for:" in check_list

    def test_includes_check_ids(self):
        check = AiToolPoisoningCheck()
        check_list = check._build_check_list()
        assert "tp001:" in check_list
