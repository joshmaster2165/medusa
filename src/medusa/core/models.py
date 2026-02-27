"""Core data models for Medusa scanner."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity level for a security finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Status(str, Enum):
    """Result status of a security check."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"


class CheckMetadata(BaseModel):
    """Metadata describing a security check."""

    check_id: str
    title: str
    category: str
    severity: Severity
    description: str
    risk_explanation: str
    remediation: str
    references: list[str] = []
    owasp_mcp: list[str] = []
    tags: list[str] = []


class Finding(BaseModel):
    """A single security finding produced by a check."""

    check_id: str
    check_title: str
    status: Status
    severity: Severity
    server_name: str
    server_transport: str
    resource_type: str
    resource_name: str
    status_extended: str
    evidence: str | None = None
    remediation: str
    owasp_mcp: list[str] = []
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ServerScore(BaseModel):
    """Security score for a single MCP server."""

    server_name: str
    score: float
    grade: str
    total_checks: int
    passed: int
    failed: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int


class ScanResult(BaseModel):
    """Complete result of a Medusa scan."""

    scan_id: str
    timestamp: datetime
    medusa_version: str
    scan_duration_seconds: float
    servers_scanned: int
    total_findings: int
    findings: list[Finding]
    server_scores: list[ServerScore]
    aggregate_score: float
    aggregate_grade: str
    compliance_results: dict[str, dict] = {}
