"""Tests for transport-aware check filtering in the scanner."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import (
    CheckMetadata,
    Finding,
    Severity,
    Status,
)
from medusa.core.registry import CheckRegistry
from medusa.core.scanner import ScanEngine


def _make_snapshot(name: str = "test-server", transport: str = "stdio") -> ServerSnapshot:
    return ServerSnapshot(
        server_name=name,
        transport_type=transport,
        tools=[{"name": "test_tool"}],
        resources=[],
        prompts=[],
    )


def _make_check(
    check_id: str,
    applicable_transports: list[str] | None = None,
    severity: Severity = Severity.HIGH,
) -> BaseCheck:
    """Create a mock check that returns one PASS finding."""
    meta = CheckMetadata(
        check_id=check_id,
        title=f"Test {check_id}",
        category="test",
        severity=severity,
        description="test",
        risk_explanation="test",
        remediation="test",
        applicable_transports=applicable_transports,
    )

    check = MagicMock(spec=BaseCheck)
    check.metadata.return_value = meta

    async def fake_execute(snapshot):
        return [
            Finding(
                check_id=check_id,
                check_title=f"Test {check_id}",
                status=Status.PASS,
                severity=severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended="OK",
                remediation="test",
            )
        ]

    check.execute = AsyncMock(side_effect=fake_execute)
    return check


def _make_fail_check(
    check_id: str,
    applicable_transports: list[str] | None = None,
) -> BaseCheck:
    """Create a mock check that returns one FAIL finding."""
    meta = CheckMetadata(
        check_id=check_id,
        title=f"Test {check_id}",
        category="test",
        severity=Severity.HIGH,
        description="test",
        risk_explanation="test",
        remediation="test",
        applicable_transports=applicable_transports,
    )

    check = MagicMock(spec=BaseCheck)
    check.metadata.return_value = meta

    async def fake_execute(snapshot):
        return [
            Finding(
                check_id=check_id,
                check_title=f"Test {check_id}",
                status=Status.FAIL,
                severity=Severity.HIGH,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended="Missing config",
                remediation="Add config",
            )
        ]

    check.execute = AsyncMock(side_effect=fake_execute)
    return check


# ── CheckMetadata.applicable_transports ──────────────────────────────────────


class TestCheckMetadataTransports:
    def test_default_is_none(self):
        meta = CheckMetadata(
            check_id="t1",
            title="Test",
            category="test",
            severity=Severity.HIGH,
            description="test",
            risk_explanation="test",
            remediation="test",
        )
        assert meta.applicable_transports is None

    def test_can_set_http_only(self):
        meta = CheckMetadata(
            check_id="t1",
            title="Test",
            category="test",
            severity=Severity.HIGH,
            description="test",
            risk_explanation="test",
            remediation="test",
            applicable_transports=["http"],
        )
        assert meta.applicable_transports == ["http"]

    def test_can_set_multiple_transports(self):
        meta = CheckMetadata(
            check_id="t1",
            title="Test",
            category="test",
            severity=Severity.HIGH,
            description="test",
            risk_explanation="test",
            remediation="test",
            applicable_transports=["http", "sse"],
        )
        assert "http" in meta.applicable_transports
        assert "sse" in meta.applicable_transports


# ── _filter_checks_for_transport ─────────────────────────────────────────────


class TestFilterChecksForTransport:
    def _make_engine(self, checks: list[BaseCheck]) -> ScanEngine:
        registry = MagicMock(spec=CheckRegistry)
        registry.get_checks.return_value = checks
        engine = ScanEngine(
            connectors=[],
            registry=registry,
        )
        engine.checks = checks
        return engine

    def test_no_transports_means_all_apply(self):
        """Checks with applicable_transports=None run on all transports."""
        check = _make_check("t1", applicable_transports=None)
        engine = self._make_engine([check])
        snapshot = _make_snapshot(transport="stdio")
        result = engine._filter_checks_for_transport(snapshot)
        assert len(result) == 1

    def test_http_only_check_skipped_for_stdio(self):
        """HTTP-only checks are skipped for stdio servers."""
        check = _make_check("t1", applicable_transports=["http"])
        engine = self._make_engine([check])
        snapshot = _make_snapshot(transport="stdio")
        result = engine._filter_checks_for_transport(snapshot)
        assert len(result) == 0

    def test_http_only_check_runs_for_http(self):
        """HTTP-only checks run on http servers."""
        check = _make_check("t1", applicable_transports=["http"])
        engine = self._make_engine([check])
        snapshot = _make_snapshot(transport="http")
        result = engine._filter_checks_for_transport(snapshot)
        assert len(result) == 1

    def test_mixed_checks_filtered_correctly(self):
        """Mix of universal and HTTP-only checks are filtered."""
        universal = _make_check("u1", applicable_transports=None)
        http_only = _make_check("h1", applicable_transports=["http"])
        engine = self._make_engine([universal, http_only])

        # stdio snapshot: only universal runs
        stdio_snap = _make_snapshot(transport="stdio")
        result = engine._filter_checks_for_transport(stdio_snap)
        assert len(result) == 1
        assert result[0].metadata().check_id == "u1"

        # http snapshot: both run
        http_snap = _make_snapshot(transport="http")
        result = engine._filter_checks_for_transport(http_snap)
        assert len(result) == 2


# ── Integration: _scan_server with transport filtering ───────────────────────


class TestScanServerTransportFiltering:
    def test_http_only_checks_not_run_on_stdio(self):
        """HTTP-only checks produce no findings for stdio servers."""
        universal = _make_fail_check("u1", applicable_transports=None)
        http_only = _make_fail_check("h1", applicable_transports=["http"])

        registry = MagicMock(spec=CheckRegistry)
        registry.get_checks.return_value = [universal, http_only]
        engine = ScanEngine(connectors=[], registry=registry)
        engine.checks = [universal, http_only]

        snapshot = _make_snapshot(transport="stdio")
        findings = asyncio.run(engine._scan_server(snapshot))

        check_ids = [f.check_id for f in findings]
        assert "u1" in check_ids
        assert "h1" not in check_ids

    def test_all_checks_run_on_http(self):
        """All checks (universal + HTTP-only) run on http servers."""
        universal = _make_fail_check("u1", applicable_transports=None)
        http_only = _make_fail_check("h1", applicable_transports=["http"])

        registry = MagicMock(spec=CheckRegistry)
        registry.get_checks.return_value = [universal, http_only]
        engine = ScanEngine(connectors=[], registry=registry)
        engine.checks = [universal, http_only]

        snapshot = _make_snapshot(transport="http")
        findings = asyncio.run(engine._scan_server(snapshot))

        check_ids = [f.check_id for f in findings]
        assert "u1" in check_ids
        assert "h1" in check_ids

    def test_progress_emitted_for_skipped_checks(self):
        """Skipped checks still emit progress events."""
        http_only = _make_check("h1", applicable_transports=["http"])
        events = []

        registry = MagicMock(spec=CheckRegistry)
        registry.get_checks.return_value = [http_only]
        engine = ScanEngine(connectors=[], registry=registry)
        engine.checks = [http_only]
        engine.progress_callback = lambda event, detail: events.append((event, detail))

        snapshot = _make_snapshot(transport="stdio")
        asyncio.run(engine._scan_server(snapshot))

        check_done_events = [e for e in events if e[0] == "check_done"]
        # Should have 1 event for the skipped check
        assert len(check_done_events) == 1
        assert check_done_events[0][1] == "transport_skipped"


# ── Real metadata files have applicable_transports ───────────────────────────


class TestRealMetadataFiles:
    """Verify that the tagged metadata files load correctly."""

    def test_shadow007_has_http_transport(self):
        from medusa.core.check import _load_metadata_yaml

        # Clear cache first
        _load_metadata_yaml.cache_clear()
        from pathlib import Path

        checks_dir = (
            Path(__file__).parent.parent.parent / "src" / "medusa" / "checks" / "server_identity"
        )
        meta_file = checks_dir / "shadow007_unauthorized_server_registration.metadata.yaml"
        if meta_file.exists():
            meta = _load_metadata_yaml(str(meta_file))
            assert meta.applicable_transports == ["http"]

    def test_dp008_has_http_transport(self):
        from medusa.core.check import _load_metadata_yaml

        _load_metadata_yaml.cache_clear()
        from pathlib import Path

        checks_dir = (
            Path(__file__).parent.parent.parent / "src" / "medusa" / "checks" / "data_protection"
        )
        meta_file = checks_dir / "dp008_cross_origin_data_sharing.metadata.yaml"
        if meta_file.exists():
            meta = _load_metadata_yaml(str(meta_file))
            assert meta.applicable_transports == ["http"]

    def test_intg007_has_http_transport(self):
        from medusa.core.check import _load_metadata_yaml

        _load_metadata_yaml.cache_clear()
        from pathlib import Path

        checks_dir = Path(__file__).parent.parent.parent / "src" / "medusa" / "checks" / "integrity"
        meta_file = checks_dir / "intg007_unsigned_updates.metadata.yaml"
        if meta_file.exists():
            meta = _load_metadata_yaml(str(meta_file))
            assert meta.applicable_transports == ["http"]
