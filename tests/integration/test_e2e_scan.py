"""End-to-end integration tests using real mock MCP servers.

Each test spins up a mock server via stdio, runs the full Medusa scan
pipeline, and asserts on the resulting findings and scores.
"""

from __future__ import annotations

import json

import pytest

from medusa.core.models import Severity, Status
from medusa.core.registry import CheckRegistry
from medusa.core.scanner import ScanEngine
from medusa.reporters.json_reporter import JsonReporter
from medusa.reporters.sarif_reporter import SarifReporter


def _build_engine(connectors, **kwargs) -> ScanEngine:
    """Build a ScanEngine with all checks discovered."""
    registry = CheckRegistry()
    registry.discover_checks()
    return ScanEngine(
        connectors=connectors,
        registry=registry,
        **kwargs,
    )


# ─── Vulnerable server ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_vulnerable_server_produces_failures(
    vulnerable_connector,
):
    """Scanning the vulnerable server should yield FAIL findings."""
    engine = _build_engine([vulnerable_connector])
    result = await engine.scan()

    fail_findings = [
        f for f in result.findings if f.status == Status.FAIL
    ]
    assert len(fail_findings) > 0, (
        "Expected FAIL findings from the vulnerable server"
    )


@pytest.mark.asyncio
async def test_vulnerable_server_detects_hidden_instructions(
    vulnerable_connector,
):
    """TP-001 should fire on the <IMPORTANT> tag."""
    engine = _build_engine([vulnerable_connector])
    result = await engine.scan()

    tp001_fails = [
        f
        for f in result.findings
        if f.check_id == "tp001" and f.status == Status.FAIL
    ]
    assert len(tp001_fails) >= 1


@pytest.mark.asyncio
async def test_vulnerable_server_detects_injection_phrases(
    vulnerable_connector,
):
    """TP-002 should fire on 'ignore previous instructions'."""
    engine = _build_engine([vulnerable_connector])
    result = await engine.scan()

    tp002_fails = [
        f
        for f in result.findings
        if f.check_id == "tp002" and f.status == Status.FAIL
    ]
    assert len(tp002_fails) >= 1


@pytest.mark.asyncio
async def test_vulnerable_server_detects_command_injection(
    vulnerable_connector,
):
    """IV-001 should fire on 'command' parameter."""
    engine = _build_engine([vulnerable_connector])
    result = await engine.scan()

    iv001_fails = [
        f
        for f in result.findings
        if f.check_id == "iv001" and f.status == Status.FAIL
    ]
    assert len(iv001_fails) >= 1


@pytest.mark.asyncio
async def test_vulnerable_server_score_below_threshold(
    vulnerable_connector,
):
    """The vulnerable server should score below 8.0."""
    engine = _build_engine([vulnerable_connector])
    result = await engine.scan()

    assert result.servers_scanned == 1
    assert result.aggregate_score < 8.0


# ─── Secure server ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_secure_server_no_critical_findings(
    secure_connector,
):
    """Secure server should have zero CRITICAL FAIL findings."""
    engine = _build_engine([secure_connector])
    result = await engine.scan()

    critical_fails = [
        f
        for f in result.findings
        if f.status == Status.FAIL
        and f.severity == Severity.CRITICAL
    ]
    assert len(critical_fails) == 0, (
        f"Unexpected CRITICAL findings: {critical_fails}"
    )


@pytest.mark.asyncio
async def test_secure_server_high_score(secure_connector):
    """Secure server should score >= 8.0."""
    engine = _build_engine([secure_connector])
    result = await engine.scan()

    assert result.servers_scanned == 1
    assert result.aggregate_score >= 8.0


# ─── Empty server ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_empty_server_completes(empty_connector):
    """Empty server should complete without errors."""
    engine = _build_engine([empty_connector])
    result = await engine.scan()

    assert result.servers_scanned == 1
    error_findings = [
        f for f in result.findings if f.status == Status.ERROR
    ]
    assert len(error_findings) == 0, (
        f"Unexpected errors: {error_findings}"
    )


# ─── Multi-server / parallel ────────────────────────────────────────


@pytest.mark.asyncio
async def test_multi_server_parallel_scan(
    vulnerable_connector,
    secure_connector,
):
    """Scanning two servers should produce results for both."""
    engine = _build_engine(
        [vulnerable_connector, secure_connector],
        max_concurrency=2,
    )
    result = await engine.scan()

    assert result.servers_scanned == 2
    server_names = {s.server_name for s in result.server_scores}
    assert "mock-vulnerable" in server_names
    assert "mock-secure" in server_names


@pytest.mark.asyncio
async def test_parallel_vs_sequential_equivalence(
    vulnerable_connector,
):
    """Parallel and sequential scans should yield the same check IDs."""
    # Parallel (default)
    engine_parallel = _build_engine(
        [vulnerable_connector], max_concurrency=4
    )
    result_parallel = await engine_parallel.scan()

    # Sequential (concurrency=1)
    engine_seq = _build_engine(
        [vulnerable_connector], max_concurrency=1
    )
    result_seq = await engine_seq.scan()

    ids_parallel = sorted(
        f.check_id for f in result_parallel.findings
    )
    ids_seq = sorted(f.check_id for f in result_seq.findings)
    assert ids_parallel == ids_seq


# ─── Progress callback ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_progress_callback_fires(secure_connector):
    """Progress callback should fire for each check and server."""
    events: list[tuple[str, str]] = []

    def on_progress(event: str, detail: str) -> None:
        events.append((event, detail))

    engine = _build_engine([secure_connector])
    engine.progress_callback = on_progress
    await engine.scan()

    event_types = {e[0] for e in events}
    assert "server_start" in event_types
    assert "server_done" in event_types
    assert "check_done" in event_types


# ─── JSON reporter ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_json_reporter_valid_output(secure_connector):
    """JSON reporter should produce valid JSON from a real scan."""
    engine = _build_engine([secure_connector])
    result = await engine.scan()

    reporter = JsonReporter()
    output = reporter.generate(result)
    data = json.loads(output)

    assert "findings" in data
    assert data["servers_scanned"] == 1


# ─── SARIF reporter ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sarif_reporter_valid_output(
    vulnerable_connector,
):
    """SARIF reporter should produce valid SARIF 2.1.0 JSON."""
    engine = _build_engine([vulnerable_connector])
    result = await engine.scan()

    reporter = SarifReporter()
    output = reporter.generate(result)
    data = json.loads(output)

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "Medusa"
    assert len(run["results"]) > 0
    assert len(run["tool"]["driver"]["rules"]) > 0


@pytest.mark.asyncio
async def test_sarif_only_fail_findings(secure_connector):
    """SARIF results should only include FAIL findings."""
    engine = _build_engine([secure_connector])
    result = await engine.scan()

    fail_count = sum(
        1 for f in result.findings if f.status == Status.FAIL
    )

    reporter = SarifReporter()
    output = reporter.generate(result)
    data = json.loads(output)

    sarif_result_count = len(data["runs"][0]["results"])
    assert sarif_result_count == fail_count
