"""Data models for the AI Reasoning Layer.

These models define the structured output of the reasoning engine,
which annotates, correlates, and extends static scan findings.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Confidence(StrEnum):
    """AI confidence in a finding's validity."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNCERTAIN = "uncertain"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    FALSE_POSITIVE = "false_positive"


class FalsePositiveReason(StrEnum):
    """Why AI considers a finding a false positive."""

    DOCUMENTATION_CONTEXT = "documentation_context"
    EXAMPLE_CODE = "example_code"
    SECURITY_MEASURE = "security_measure"
    NEGATION_CONTEXT = "negation_context"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    SEMANTIC_MISUNDERSTANDING = "semantic_misunderstanding"
    BENIGN_PATTERN = "benign_pattern"


class FindingAnnotation(BaseModel):
    """AI annotation for a single static finding."""

    check_id: str
    resource_name: str
    confidence: Confidence
    confidence_score: float = Field(ge=0.0, le=1.0)
    reasoning: str
    false_positive_reason: FalsePositiveReason | None = None
    exploitability_note: str | None = None
    adjusted_severity: str | None = None
    additional_context: str | None = None
    contradicting_evidence: str | None = None


class AttackChain(BaseModel):
    """A correlated set of findings that form an attack chain."""

    chain_id: str
    title: str
    description: str
    severity: str
    finding_check_ids: list[str]
    finding_resource_names: list[str]
    attack_narrative: str
    impact: str
    owasp_mcp: list[str] = []


class GapFinding(BaseModel):
    """A new finding discovered by AI that static checks missed."""

    title: str
    severity: str
    resource_type: str
    resource_name: str
    description: str
    evidence: str
    remediation: str
    owasp_mcp: list[str] = []
    reasoning: str


class ReasoningResult(BaseModel):
    """Complete output from the AI Reasoning Layer for one server."""

    server_name: str
    reasoning_model: str = ""
    reasoning_duration_seconds: float = 0.0
    token_usage: dict[str, Any] = {}

    # Core outputs
    annotations: list[FindingAnnotation] = []
    attack_chains: list[AttackChain] = []
    gap_findings: list[GapFinding] = []

    # Summary
    executive_summary: str = ""
    risk_narrative: str = ""
    top_priorities: list[str] = []

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
