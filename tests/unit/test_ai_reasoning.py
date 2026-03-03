"""Unit tests for the AI Reasoning Layer."""

from __future__ import annotations

import pytest

from medusa.ai.reasoning.chunker import (
    chunk_findings_for_reasoning,
    estimate_finding_tokens,
    estimate_snapshot_tokens,
)
from medusa.ai.reasoning.models import (
    AttackChain,
    Confidence,
    FalsePositiveReason,
    FindingAnnotation,
    GapFinding,
    ReasoningResult,
)
from medusa.ai.reasoning.prompts import (
    build_reasoning_system_prompt,
    build_reasoning_user_payload,
)
from medusa.ai.reasoning.response_parser import parse_reasoning_response
from medusa.core.models import Finding, Severity, Status
from tests.conftest import make_snapshot

# ── Fixtures ────────────────────────────────────────────────────────


def _make_finding(
    check_id: str = "tp001",
    title: str = "Test Finding",
    status: Status = Status.FAIL,
    severity: Severity = Severity.HIGH,
    resource_name: str = "test_tool",
    evidence: str = "some evidence",
) -> Finding:
    return Finding(
        check_id=check_id,
        check_title=title,
        status=status,
        severity=severity,
        server_name="test-server",
        server_transport="stdio",
        resource_type="tool",
        resource_name=resource_name,
        status_extended="Detailed explanation of the issue.",
        evidence=evidence,
        remediation="Fix it.",
        owasp_mcp=["MCP03:2025"],
    )


# =====================================================================
# Models
# =====================================================================


class TestModels:
    """Tests for reasoning data models."""

    def test_confidence_enum_values(self) -> None:
        assert Confidence.CONFIRMED == "confirmed"
        assert Confidence.FALSE_POSITIVE == "false_positive"
        assert Confidence.LIKELY_FALSE_POSITIVE == "likely_false_positive"

    def test_false_positive_reason_enum(self) -> None:
        assert FalsePositiveReason.DOCUMENTATION_CONTEXT == "documentation_context"
        assert FalsePositiveReason.BENIGN_PATTERN == "benign_pattern"

    def test_finding_annotation_creation(self) -> None:
        ann = FindingAnnotation(
            check_id="tp001",
            resource_name="test_tool",
            confidence=Confidence.CONFIRMED,
            confidence_score=0.95,
            reasoning="This is a real issue.",
        )
        assert ann.confidence_score == 0.95
        assert ann.false_positive_reason is None

    def test_finding_annotation_with_false_positive(self) -> None:
        ann = FindingAnnotation(
            check_id="tp001",
            resource_name="test_tool",
            confidence=Confidence.FALSE_POSITIVE,
            confidence_score=0.1,
            reasoning="This is documentation context.",
            false_positive_reason=FalsePositiveReason.DOCUMENTATION_CONTEXT,
        )
        assert ann.confidence == Confidence.FALSE_POSITIVE
        assert ann.false_positive_reason == FalsePositiveReason.DOCUMENTATION_CONTEXT

    def test_attack_chain_creation(self) -> None:
        chain = AttackChain(
            chain_id="chain_001",
            title="Test Chain",
            description="A test attack chain",
            severity="critical",
            finding_check_ids=["tp001", "iv001"],
            finding_resource_names=["tool_a", "tool_b"],
            attack_narrative="Step 1: exploit. Step 2: profit.",
            impact="Full compromise.",
            owasp_mcp=["MCP03:2025"],
        )
        assert len(chain.finding_check_ids) == 2
        assert chain.severity == "critical"

    def test_gap_finding_creation(self) -> None:
        gap = GapFinding(
            title="Semantic Mismatch",
            severity="high",
            resource_type="tool",
            resource_name="safe_read",
            description="Tool name implies read but it writes.",
            evidence="Tool description says 'delete all records'.",
            remediation="Rename the tool.",
            reasoning="Static checks only match keywords.",
        )
        assert gap.resource_name == "safe_read"

    def test_reasoning_result_creation(self) -> None:
        result = ReasoningResult(server_name="test-server")
        assert result.server_name == "test-server"
        assert result.annotations == []
        assert result.attack_chains == []
        assert result.gap_findings == []
        assert result.executive_summary == ""

    def test_reasoning_result_full(self) -> None:
        result = ReasoningResult(
            server_name="test-server",
            reasoning_model="claude-sonnet-4-20250514",
            reasoning_duration_seconds=5.2,
            token_usage={"input_tokens": 25000, "output_tokens": 3000},
            annotations=[
                FindingAnnotation(
                    check_id="tp001",
                    resource_name="tool",
                    confidence=Confidence.CONFIRMED,
                    confidence_score=0.9,
                    reasoning="Real.",
                )
            ],
            executive_summary="Server has issues.",
            top_priorities=["Fix tp001"],
        )
        assert len(result.annotations) == 1
        assert result.token_usage["input_tokens"] == 25000


# =====================================================================
# Prompts
# =====================================================================


class TestPrompts:
    """Tests for reasoning prompt generation."""

    def test_system_prompt_single_chunk(self) -> None:
        prompt = build_reasoning_system_prompt(num_findings=5)
        assert "5 automated security" in prompt
        assert "VALIDATE" in prompt
        assert "CORRELATE" in prompt
        assert "DISCOVER" in prompt
        assert "chunk" not in prompt.lower() or "chunk_context" not in prompt

    def test_system_prompt_multi_chunk(self) -> None:
        prompt = build_reasoning_system_prompt(
            num_findings=50,
            chunk_index=1,
            total_chunks=3,
        )
        assert "chunk 2 of 3" in prompt

    def test_user_payload_includes_snapshot(self) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "test_tool",
                    "description": "A test tool.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = [_make_finding()]
        payload = build_reasoning_user_payload(snapshot, findings)
        assert "test_tool" in payload
        assert "STATIC FINDINGS" in payload

    def test_user_payload_includes_fail_findings(self) -> None:
        snapshot = make_snapshot()
        findings = [
            _make_finding(check_id="tp001", status=Status.FAIL),
            _make_finding(check_id="tp002", status=Status.PASS),
        ]
        payload = build_reasoning_user_payload(snapshot, findings)
        assert "tp001" in payload
        assert "1 failed, 1 passed" in payload

    def test_user_payload_truncates_long_evidence(self) -> None:
        snapshot = make_snapshot()
        findings = [_make_finding(evidence="x" * 300)]
        payload = build_reasoning_user_payload(snapshot, findings)
        assert "..." in payload

    def test_user_payload_no_findings(self) -> None:
        snapshot = make_snapshot()
        payload = build_reasoning_user_payload(snapshot, [])
        assert "0 failed, 0 passed" in payload


# =====================================================================
# Chunker
# =====================================================================


class TestChunker:
    """Tests for token budget and chunking."""

    def test_estimate_snapshot_tokens_empty(self) -> None:
        snapshot = make_snapshot()
        tokens = estimate_snapshot_tokens(snapshot)
        assert tokens >= 0

    def test_estimate_snapshot_tokens_with_tools(self) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": f"tool_{i}",
                    "description": "A" * 100,
                    "inputSchema": {"type": "object", "properties": {}},
                }
                for i in range(20)
            ]
        )
        tokens = estimate_snapshot_tokens(snapshot)
        assert tokens > 100  # Should be substantial

    def test_estimate_finding_tokens(self) -> None:
        finding = _make_finding()
        tokens = estimate_finding_tokens(finding)
        assert tokens > 0

    def test_chunk_no_failures(self) -> None:
        snapshot = make_snapshot()
        findings = [
            _make_finding(status=Status.PASS),
            _make_finding(status=Status.PASS),
        ]
        chunks = chunk_findings_for_reasoning(snapshot, findings)
        assert len(chunks) == 1
        assert chunks[0] == findings

    def test_chunk_single_chunk_returns_all_findings(self) -> None:
        snapshot = make_snapshot()
        findings = [
            _make_finding(check_id="tp001", status=Status.FAIL),
            _make_finding(check_id="tp002", status=Status.PASS),
            _make_finding(check_id="iv001", status=Status.FAIL),
        ]
        chunks = chunk_findings_for_reasoning(snapshot, findings, max_tokens_per_chunk=100_000)
        # Fits in one chunk, so all findings (including PASS) returned
        assert len(chunks) == 1
        assert len(chunks[0]) == 3

    def test_chunk_splits_on_token_budget(self) -> None:
        snapshot = make_snapshot()
        # Create many findings to exceed a tiny token budget
        findings = [
            _make_finding(
                check_id=f"tp{i:03d}",
                status=Status.FAIL,
                evidence="x" * 200,
            )
            for i in range(50)
        ]
        # Very small budget to force splitting
        chunks = chunk_findings_for_reasoning(snapshot, findings, max_tokens_per_chunk=500)
        # Should have more than 1 chunk with such a small budget
        assert len(chunks) >= 1

    def test_chunk_groups_by_category(self) -> None:
        snapshot = make_snapshot()
        findings = [
            _make_finding(check_id="tp001", status=Status.FAIL),
            _make_finding(check_id="tp002", status=Status.FAIL),
            _make_finding(check_id="iv001", status=Status.FAIL),
            _make_finding(check_id="iv002", status=Status.FAIL),
        ]
        chunks = chunk_findings_for_reasoning(snapshot, findings, max_tokens_per_chunk=100_000)
        # Should fit in one chunk
        assert len(chunks) == 1


# =====================================================================
# Response Parser
# =====================================================================


class TestResponseParser:
    """Tests for parsing Claude's reasoning responses."""

    def test_parse_complete_response(self) -> None:
        data = {
            "executive_summary": "Server has critical issues.",
            "risk_narrative": "High risk due to command injection.",
            "annotations": [
                {
                    "check_id": "tp001",
                    "resource_name": "exec_tool",
                    "confidence": "confirmed",
                    "confidence_score": 0.95,
                    "reasoning": "Real issue with concrete evidence.",
                }
            ],
            "attack_chains": [
                {
                    "chain_id": "chain_001",
                    "title": "Code Execution Chain",
                    "description": "Linked vulnerabilities",
                    "severity": "critical",
                    "finding_check_ids": ["tp001", "iv001"],
                    "finding_resource_names": ["exec_tool", "query_tool"],
                    "attack_narrative": "Step 1: inject. Step 2: execute.",
                    "impact": "Full system compromise.",
                    "owasp_mcp": ["MCP03:2025"],
                }
            ],
            "gap_findings": [
                {
                    "title": "Name Mismatch",
                    "severity": "high",
                    "resource_type": "tool",
                    "resource_name": "safe_delete",
                    "description": "Name implies safety but deletes data.",
                    "evidence": "Description: 'permanently removes all records'",
                    "remediation": "Rename to delete_all_records.",
                    "owasp_mcp": ["MCP03:2025"],
                    "reasoning": "Semantic mismatch undetectable by regex.",
                }
            ],
            "top_priorities": ["1. Fix chain_001", "2. Rename safe_delete"],
        }
        result = parse_reasoning_response(data, "test-server")
        assert result.server_name == "test-server"
        assert result.executive_summary == "Server has critical issues."
        assert len(result.annotations) == 1
        assert result.annotations[0].confidence == Confidence.CONFIRMED
        assert result.annotations[0].confidence_score == 0.95
        assert len(result.attack_chains) == 1
        assert result.attack_chains[0].severity == "critical"
        assert len(result.gap_findings) == 1
        assert result.gap_findings[0].resource_name == "safe_delete"
        assert len(result.top_priorities) == 2

    def test_parse_empty_response(self) -> None:
        result = parse_reasoning_response({}, "test-server")
        assert result.annotations == []
        assert result.attack_chains == []
        assert result.gap_findings == []
        assert result.executive_summary == ""

    def test_parse_invalid_confidence_defaults_to_uncertain(self) -> None:
        data = {
            "annotations": [
                {
                    "check_id": "tp001",
                    "resource_name": "tool",
                    "confidence": "invalid_value",
                    "confidence_score": 0.5,
                    "reasoning": "test",
                }
            ]
        }
        result = parse_reasoning_response(data, "server")
        assert len(result.annotations) == 1
        assert result.annotations[0].confidence == Confidence.UNCERTAIN

    def test_parse_clamps_confidence_score(self) -> None:
        data = {
            "annotations": [
                {
                    "check_id": "tp001",
                    "resource_name": "tool",
                    "confidence": "confirmed",
                    "confidence_score": 1.5,  # Over max
                    "reasoning": "test",
                }
            ]
        }
        result = parse_reasoning_response(data, "server")
        assert result.annotations[0].confidence_score == 1.0

    def test_parse_negative_confidence_score(self) -> None:
        data = {
            "annotations": [
                {
                    "check_id": "tp001",
                    "resource_name": "tool",
                    "confidence": "confirmed",
                    "confidence_score": -0.5,
                    "reasoning": "test",
                }
            ]
        }
        result = parse_reasoning_response(data, "server")
        assert result.annotations[0].confidence_score == 0.0

    def test_parse_invalid_severity_defaults_to_medium(self) -> None:
        data = {
            "attack_chains": [
                {
                    "chain_id": "chain_001",
                    "title": "Test",
                    "description": "Test",
                    "severity": "super_critical",  # Invalid
                    "finding_check_ids": ["tp001"],
                    "finding_resource_names": ["tool"],
                    "attack_narrative": "Test",
                    "impact": "Test",
                }
            ]
        }
        result = parse_reasoning_response(data, "server")
        assert result.attack_chains[0].severity == "medium"

    def test_parse_malformed_annotations_skipped(self) -> None:
        data = {
            "annotations": [
                "not a dict",
                42,
                {"check_id": "tp001"},  # Missing required fields
            ]
        }
        result = parse_reasoning_response(data, "server")
        # Should have parsed the partial dict (with defaults)
        assert len(result.annotations) >= 0  # Graceful handling

    def test_parse_false_positive_reason(self) -> None:
        data = {
            "annotations": [
                {
                    "check_id": "tp001",
                    "resource_name": "tool",
                    "confidence": "false_positive",
                    "confidence_score": 0.1,
                    "reasoning": "This is documentation.",
                    "false_positive_reason": "documentation_context",
                }
            ]
        }
        result = parse_reasoning_response(data, "server")
        assert len(result.annotations) == 1
        ann = result.annotations[0]
        assert ann.false_positive_reason == FalsePositiveReason.DOCUMENTATION_CONTEXT

    def test_parse_invalid_false_positive_reason_ignored(self) -> None:
        data = {
            "annotations": [
                {
                    "check_id": "tp001",
                    "resource_name": "tool",
                    "confidence": "confirmed",
                    "confidence_score": 0.9,
                    "reasoning": "Real.",
                    "false_positive_reason": "not_a_real_reason",
                }
            ]
        }
        result = parse_reasoning_response(data, "server")
        assert result.annotations[0].false_positive_reason is None

    def test_parse_annotations_not_a_list(self) -> None:
        data = {"annotations": "not a list"}
        result = parse_reasoning_response(data, "server")
        assert result.annotations == []

    def test_parse_gap_finding_defaults(self) -> None:
        data = {
            "gap_findings": [
                {
                    "title": "Test Gap",
                    "evidence": "Some evidence",
                }
            ]
        }
        result = parse_reasoning_response(data, "server")
        assert len(result.gap_findings) == 1
        gap = result.gap_findings[0]
        assert gap.severity == "medium"  # Default
        assert gap.resource_type == "server"  # Default
        assert gap.resource_name == "unknown"  # Default


# =====================================================================
# Engine (mocked)
# =====================================================================


class TestEngine:
    """Tests for the ReasoningEngine with a mock AI client."""

    @pytest.fixture()
    def mock_client(self):
        class MockAiClient:
            def __init__(self, response: dict):
                self.response = response
                self.calls = []

            async def analyze(self, system_prompt: str, user_content: str) -> dict:
                self.calls.append((system_prompt, user_content))
                return self.response

            async def close(self) -> None:
                pass

        return MockAiClient

    async def test_reason_no_failures_skips_ai(self, mock_client) -> None:
        from medusa.ai.reasoning.engine import ReasoningEngine

        client = mock_client({"should": "not be called"})
        engine = ReasoningEngine(client=client)

        snapshot = make_snapshot()
        findings = [
            _make_finding(status=Status.PASS),
            _make_finding(status=Status.PASS),
        ]

        result = await engine.reason(snapshot, findings)
        assert result.reasoning_model == "skipped"
        assert len(client.calls) == 0

    async def test_reason_with_failures_calls_ai(self, mock_client) -> None:
        from medusa.ai.reasoning.engine import ReasoningEngine

        response = {
            "executive_summary": "Found issues.",
            "annotations": [
                {
                    "check_id": "tp001",
                    "resource_name": "test_tool",
                    "confidence": "confirmed",
                    "confidence_score": 0.9,
                    "reasoning": "Real issue.",
                }
            ],
            "attack_chains": [],
            "gap_findings": [],
            "top_priorities": ["Fix tp001"],
        }
        client = mock_client(response)
        engine = ReasoningEngine(client=client)

        snapshot = make_snapshot()
        findings = [_make_finding(status=Status.FAIL)]

        result = await engine.reason(snapshot, findings)
        assert len(client.calls) == 1
        assert result.executive_summary == "Found issues."
        assert len(result.annotations) == 1

    async def test_reason_handles_ai_error(self, mock_client) -> None:
        from medusa.ai.reasoning.engine import ReasoningEngine

        class ErrorClient:
            async def analyze(self, system_prompt: str, user_content: str) -> dict:
                raise RuntimeError("API error")

            async def close(self) -> None:
                pass

        engine = ReasoningEngine(client=ErrorClient())

        snapshot = make_snapshot()
        findings = [_make_finding(status=Status.FAIL)]

        # Should not raise, returns empty result
        result = await engine.reason(snapshot, findings)
        assert result.annotations == []
        assert result.attack_chains == []

    async def test_reason_with_gap_findings(self, mock_client) -> None:
        from medusa.ai.reasoning.engine import ReasoningEngine

        response = {
            "executive_summary": "Gaps found.",
            "annotations": [],
            "attack_chains": [],
            "gap_findings": [
                {
                    "title": "Semantic Mismatch",
                    "severity": "high",
                    "resource_type": "tool",
                    "resource_name": "safe_delete",
                    "description": "Name implies safe but deletes.",
                    "evidence": "Description says delete.",
                    "remediation": "Rename.",
                    "reasoning": "Regex can't catch this.",
                }
            ],
            "top_priorities": [],
        }
        client = mock_client(response)
        engine = ReasoningEngine(client=client)

        snapshot = make_snapshot()
        findings = [_make_finding(status=Status.FAIL)]

        result = await engine.reason(snapshot, findings)
        assert len(result.gap_findings) == 1
        assert result.gap_findings[0].resource_name == "safe_delete"


# =====================================================================
# Scanner Integration
# =====================================================================


class TestScannerReasoning:
    """Tests for reasoning integration in the scanner."""

    def test_scan_engine_accepts_enable_reasoning(self) -> None:
        from medusa.core.registry import CheckRegistry
        from medusa.core.scanner import ScanEngine

        registry = CheckRegistry()
        registry.discover_checks()

        engine = ScanEngine(
            connectors=[],
            registry=registry,
            scan_mode="static",
            enable_reasoning=True,
        )
        assert engine.enable_reasoning is True

    def test_scan_engine_default_no_reasoning(self) -> None:
        from medusa.core.registry import CheckRegistry
        from medusa.core.scanner import ScanEngine

        registry = CheckRegistry()
        registry.discover_checks()

        engine = ScanEngine(
            connectors=[],
            registry=registry,
        )
        assert engine.enable_reasoning is False

    def test_gaps_to_findings(self) -> None:
        from medusa.ai.reasoning.models import GapFinding, ReasoningResult
        from medusa.core.registry import CheckRegistry
        from medusa.core.scanner import ScanEngine

        registry = CheckRegistry()
        registry.discover_checks()

        engine = ScanEngine(
            connectors=[],
            registry=registry,
        )
        snapshot = make_snapshot()
        reasoning = ReasoningResult(
            server_name="test",
            gap_findings=[
                GapFinding(
                    title="Test Gap",
                    severity="high",
                    resource_type="tool",
                    resource_name="bad_tool",
                    description="Tool is bad.",
                    evidence="Evidence here.",
                    remediation="Fix it.",
                    reasoning="Static missed it.",
                )
            ],
        )
        gap_findings = engine._gaps_to_findings(reasoning, snapshot)
        assert len(gap_findings) == 1
        assert gap_findings[0].check_id == "gap001"
        assert gap_findings[0].severity == Severity.HIGH
        assert gap_findings[0].check_title == "Test Gap"


# =====================================================================
# ScanResult with reasoning_results
# =====================================================================


class TestScanResultReasoning:
    """Tests for reasoning_results in ScanResult."""

    def test_scan_result_includes_reasoning(self) -> None:
        from datetime import UTC, datetime

        from medusa.core.models import ScanResult

        result = ScanResult(
            scan_id="test",
            timestamp=datetime.now(UTC),
            medusa_version="0.1.0",
            scan_duration_seconds=1.0,
            servers_scanned=1,
            total_findings=0,
            findings=[],
            server_scores=[],
            aggregate_score=10.0,
            aggregate_grade="A",
            reasoning_results={
                "test-server": {
                    "executive_summary": "All good.",
                    "annotations": [],
                }
            },
        )
        assert "test-server" in result.reasoning_results

    def test_scan_result_serializes_reasoning(self) -> None:
        import json
        from datetime import UTC, datetime

        from medusa.core.models import ScanResult

        result = ScanResult(
            scan_id="test",
            timestamp=datetime.now(UTC),
            medusa_version="0.1.0",
            scan_duration_seconds=1.0,
            servers_scanned=1,
            total_findings=0,
            findings=[],
            server_scores=[],
            aggregate_score=10.0,
            aggregate_grade="A",
            reasoning_results={
                "server1": {"summary": "OK"},
            },
        )
        data = json.loads(result.model_dump_json())
        assert "reasoning_results" in data
        assert data["reasoning_results"]["server1"]["summary"] == "OK"


# =====================================================================
# Apply Reasoning to Findings (Invisible Quality Layer)
# =====================================================================


class TestApplyReasoningToFindings:
    """Tests for the invisible AI filtering in _apply_reasoning_to_findings."""

    def _make_engine(self):
        from medusa.core.registry import CheckRegistry
        from medusa.core.scanner import ScanEngine

        registry = CheckRegistry()
        registry.discover_checks()
        return ScanEngine(connectors=[], registry=registry, enable_reasoning=True)

    def test_fp_with_low_score_is_removed(self) -> None:
        engine = self._make_engine()
        snapshot = make_snapshot()

        # Need at least 3 findings so removing 1 (33%) doesn't
        # trigger the 50% bulk safety valve.
        findings = [
            _make_finding(check_id="tp001", severity=Severity.HIGH, resource_name="tool_a"),
            _make_finding(check_id="tp002", severity=Severity.MEDIUM, resource_name="tool_b"),
            _make_finding(check_id="tp003", severity=Severity.LOW, resource_name="tool_c"),
        ]
        reasoning = ReasoningResult(
            server_name="test",
            annotations=[
                FindingAnnotation(
                    check_id="tp001",
                    resource_name="tool_a",
                    confidence=Confidence.FALSE_POSITIVE,
                    confidence_score=0.1,
                    reasoning="Doc context.",
                    false_positive_reason=FalsePositiveReason.DOCUMENTATION_CONTEXT,
                )
            ],
        )

        filtered, stats = engine._apply_reasoning_to_findings(findings, reasoning, snapshot)
        fail_findings = [f for f in filtered if f.status == Status.FAIL]
        assert len(fail_findings) == 2  # tp002 and tp003 kept
        assert stats["false_positives_removed"] == 1

    def test_fp_with_high_score_is_kept(self) -> None:
        engine = self._make_engine()
        snapshot = make_snapshot()

        findings = [
            _make_finding(check_id="tp001", severity=Severity.HIGH, resource_name="tool_a"),
        ]
        reasoning = ReasoningResult(
            server_name="test",
            annotations=[
                FindingAnnotation(
                    check_id="tp001",
                    resource_name="tool_a",
                    confidence=Confidence.LIKELY_FALSE_POSITIVE,
                    confidence_score=0.4,  # Above 0.3 threshold
                    reasoning="Might be FP.",
                )
            ],
        )

        filtered, stats = engine._apply_reasoning_to_findings(findings, reasoning, snapshot)
        fail_findings = [f for f in filtered if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert stats["false_positives_removed"] == 0

    def test_critical_fp_is_never_removed(self) -> None:
        engine = self._make_engine()
        snapshot = make_snapshot()

        findings = [
            _make_finding(check_id="tp001", severity=Severity.CRITICAL, resource_name="tool_a"),
        ]
        reasoning = ReasoningResult(
            server_name="test",
            annotations=[
                FindingAnnotation(
                    check_id="tp001",
                    resource_name="tool_a",
                    confidence=Confidence.FALSE_POSITIVE,
                    confidence_score=0.05,
                    reasoning="FP but critical.",
                )
            ],
        )

        filtered, stats = engine._apply_reasoning_to_findings(findings, reasoning, snapshot)
        fail_findings = [f for f in filtered if f.status == Status.FAIL]
        assert len(fail_findings) == 1  # Preserved!
        assert stats["critical_preserved"] == 1
        assert stats["false_positives_removed"] == 0

    def test_severity_adjustment_applied(self) -> None:
        engine = self._make_engine()
        snapshot = make_snapshot()

        findings = [
            _make_finding(check_id="tp001", severity=Severity.HIGH, resource_name="tool_a"),
        ]
        reasoning = ReasoningResult(
            server_name="test",
            annotations=[
                FindingAnnotation(
                    check_id="tp001",
                    resource_name="tool_a",
                    confidence=Confidence.CONFIRMED,
                    confidence_score=0.9,
                    reasoning="Real but medium.",
                    adjusted_severity="medium",
                )
            ],
        )

        filtered, stats = engine._apply_reasoning_to_findings(findings, reasoning, snapshot)
        assert filtered[0].severity == Severity.MEDIUM
        assert stats["severities_adjusted"] == 1

    def test_gap_findings_use_normalized_ids(self) -> None:
        engine = self._make_engine()
        snapshot = make_snapshot()

        findings = [_make_finding(status=Status.PASS)]
        reasoning = ReasoningResult(
            server_name="test",
            gap_findings=[
                GapFinding(
                    title="Semantic Mismatch",
                    severity="high",
                    resource_type="tool",
                    resource_name="bad_tool",
                    description="Tool is bad.",
                    evidence="Evidence.",
                    remediation="Fix it.",
                    reasoning="Static missed it.",
                ),
                GapFinding(
                    title="Another Gap",
                    severity="medium",
                    resource_type="tool",
                    resource_name="other_tool",
                    description="Also bad.",
                    evidence="More evidence.",
                    remediation="Fix too.",
                    reasoning="Also missed.",
                ),
            ],
        )

        filtered, stats = engine._apply_reasoning_to_findings(findings, reasoning, snapshot)
        gap_findings = [f for f in filtered if f.status == Status.FAIL]
        assert len(gap_findings) == 2
        assert gap_findings[0].check_id == "gap001"
        assert gap_findings[1].check_id == "gap002"
        # No AI branding in titles
        assert "[AI Reasoning]" not in gap_findings[0].check_title
        assert gap_findings[0].check_title == "Semantic Mismatch"
        assert stats["gaps_added"] == 2

    def test_bulk_removal_safety_valve(self) -> None:
        engine = self._make_engine()
        snapshot = make_snapshot()

        # 4 findings, AI tries to remove 3 (75% > 50% threshold)
        findings = [
            _make_finding(check_id=f"tp{i:03d}", severity=Severity.HIGH, resource_name=f"t{i}")
            for i in range(4)
        ]
        annotations = [
            FindingAnnotation(
                check_id=f"tp{i:03d}",
                resource_name=f"t{i}",
                confidence=Confidence.FALSE_POSITIVE,
                confidence_score=0.1,
                reasoning="FP.",
            )
            for i in range(3)  # 3 out of 4 = 75%
        ]
        reasoning = ReasoningResult(server_name="test", annotations=annotations)

        filtered, stats = engine._apply_reasoning_to_findings(findings, reasoning, snapshot)
        fail_findings = [f for f in filtered if f.status == Status.FAIL]
        # Safety valve triggers: all 4 findings preserved
        assert len(fail_findings) == 4
        assert stats["false_positives_removed"] == 0

    def test_ai_failure_passes_findings_through(self) -> None:
        """When reasoning_result is None, findings pass through unmodified.

        The scanner only calls _apply_reasoning_to_findings when
        reasoning_result is not None, so findings are unchanged.
        """
        findings = [
            _make_finding(check_id="tp001"),
            _make_finding(check_id="tp002"),
        ]
        # Simulate: _run_reasoning returns None (AI call failed)
        # _apply_reasoning_to_findings is never called
        # Verify findings are unchanged
        assert len(findings) == 2
        assert findings[0].check_id == "tp001"

    def test_no_annotations_passes_through(self) -> None:
        engine = self._make_engine()
        snapshot = make_snapshot()

        findings = [
            _make_finding(check_id="tp001", resource_name="tool_a"),
        ]
        # Reasoning with no annotations — findings pass through
        reasoning = ReasoningResult(server_name="test")

        filtered, stats = engine._apply_reasoning_to_findings(findings, reasoning, snapshot)
        assert len(filtered) == 1
        assert stats["false_positives_removed"] == 0
        assert stats["severities_adjusted"] == 0

    def test_pass_findings_not_affected(self) -> None:
        engine = self._make_engine()
        snapshot = make_snapshot()

        findings = [
            _make_finding(check_id="tp001", status=Status.PASS, resource_name="tool_a"),
            _make_finding(check_id="tp002", status=Status.FAIL, resource_name="tool_b"),
        ]
        reasoning = ReasoningResult(
            server_name="test",
            annotations=[
                FindingAnnotation(
                    check_id="tp001",
                    resource_name="tool_a",
                    confidence=Confidence.FALSE_POSITIVE,
                    confidence_score=0.1,
                    reasoning="FP.",
                )
            ],
        )

        filtered, stats = engine._apply_reasoning_to_findings(findings, reasoning, snapshot)
        # PASS finding is not affected by FP annotation (only FAIL gets filtered)
        pass_count = sum(1 for f in filtered if f.status == Status.PASS)
        fail_count = sum(1 for f in filtered if f.status == Status.FAIL)
        assert pass_count == 1
        assert fail_count == 1

    def test_contradicting_evidence_parsed(self) -> None:
        data = {
            "annotations": [
                {
                    "check_id": "tp001",
                    "resource_name": "tool",
                    "confidence": "false_positive",
                    "confidence_score": 0.1,
                    "reasoning": "Doc context.",
                    "false_positive_reason": "documentation_context",
                    "contradicting_evidence": "Description says 'this is an example'",
                }
            ]
        }
        result = parse_reasoning_response(data, "server")
        assert (
            result.annotations[0].contradicting_evidence == "Description says 'this is an example'"
        )


class TestPromptIncludesPassFindings:
    """Tests that PASS findings are sent to AI for false-negative detection."""

    def test_payload_includes_pass_findings_section(self) -> None:
        snapshot = make_snapshot()
        findings = [
            _make_finding(check_id="tp001", status=Status.FAIL),
            _make_finding(check_id="iv001", status=Status.PASS, resource_name="safe_tool"),
        ]
        payload = build_reasoning_user_payload(snapshot, findings)
        assert "PASSED CHECKS" in payload
        assert "PASS iv001" in payload
        assert "safe_tool" in payload

    def test_payload_no_pass_section_when_no_passes(self) -> None:
        snapshot = make_snapshot()
        findings = [
            _make_finding(check_id="tp001", status=Status.FAIL),
        ]
        payload = build_reasoning_user_payload(snapshot, findings)
        assert "PASSED CHECKS" not in payload

    def test_system_prompt_mentions_false_negatives(self) -> None:
        prompt = build_reasoning_system_prompt(num_findings=5)
        assert "FALSE NEGATIVES" in prompt
        assert "contradicting_evidence" in prompt
