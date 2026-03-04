"""Benchmark data models."""

from __future__ import annotations

from pydantic import BaseModel


class ServerCatalogEntry(BaseModel):
    """A server in the benchmark catalog."""

    name: str
    package: str  # npm package name
    transport: str = "stdio"
    command: str = "npx"
    args: list[str] = []
    env_required: list[str] = []  # Required env vars
    description: str = ""
    category: str = ""
    url: str = ""


class BenchmarkToolResult(BaseModel):
    """Result for a single tool in a benchmark run."""

    tool_name: str
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    critical_findings: int = 0
    high_findings: int = 0


class BenchmarkServerResult(BaseModel):
    """Result of benchmarking a single server."""

    server_name: str
    package: str
    status: str  # "scanned", "skipped", "error"
    skip_reason: str = ""
    error_message: str = ""
    score: float = 0.0
    grade: str = ""
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    tool_count: int = 0
    resource_count: int = 0
    prompt_count: int = 0
    categories_failed: list[str] = []
    top_findings: list[str] = []


class BenchmarkReport(BaseModel):
    """Complete benchmark report."""

    timestamp: str
    medusa_version: str = ""
    total_servers: int = 0
    scanned_servers: int = 0
    skipped_servers: int = 0
    average_score: float = 0.0
    results: list[BenchmarkServerResult] = []
