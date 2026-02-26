"""Scan engine that orchestrates the full Medusa scan workflow."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone

from medusa import __version__
from medusa.connectors.base import BaseConnector
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.exceptions import CheckError, ConnectionError
from medusa.core.models import Finding, ScanResult, Severity, Status
from medusa.core.registry import CheckRegistry
from medusa.core.scoring import calculate_aggregate_score, calculate_server_score, score_to_grade

logger = logging.getLogger(__name__)


class ScanEngine:
    """Orchestrates the full scan: connect -> snapshot -> check -> score -> result."""

    def __init__(
        self,
        connectors: list[BaseConnector],
        registry: CheckRegistry,
        categories: list[str] | None = None,
        severities: list[str] | None = None,
        check_ids: list[str] | None = None,
        exclude_ids: list[str] | None = None,
    ) -> None:
        self.connectors = connectors
        self.registry = registry
        self.checks = registry.get_checks(
            categories=categories,
            severities=severities,
            check_ids=check_ids,
            exclude_ids=exclude_ids,
        )

    async def _connect(self, connector: BaseConnector) -> ServerSnapshot | None:
        """Connect to a single MCP server and return its snapshot."""
        try:
            snapshot = await connector.connect_and_snapshot()
            logger.info(
                "Connected to '%s' (%s): %d tools, %d resources, %d prompts",
                snapshot.server_name,
                snapshot.transport_type,
                len(snapshot.tools),
                len(snapshot.resources),
                len(snapshot.prompts),
            )
            return snapshot
        except ConnectionError as e:
            logger.error("Connection failed: %s", e)
            return None
        except Exception as e:
            logger.error("Unexpected error connecting: %s", e)
            return None

    async def _run_check(
        self, check: BaseCheck, snapshot: ServerSnapshot
    ) -> list[Finding]:
        """Run a single check against a snapshot, catching errors."""
        meta = check.metadata()
        try:
            findings = await check.execute(snapshot)
            return findings
        except Exception as e:
            logger.error(
                "Check %s failed on server '%s': %s",
                meta.check_id,
                snapshot.server_name,
                e,
            )
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.ERROR,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=f"Check execution error: {e}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]

    async def _scan_server(self, snapshot: ServerSnapshot) -> list[Finding]:
        """Run all checks against a single server snapshot."""
        all_findings: list[Finding] = []
        for check in self.checks:
            findings = await self._run_check(check, snapshot)
            all_findings.extend(findings)
        return all_findings

    async def scan(self) -> ScanResult:
        """Execute the full scan across all configured servers."""
        start_time = time.monotonic()
        scan_id = str(uuid.uuid4())[:8]
        all_findings: list[Finding] = []
        server_scores = []
        servers_scanned = 0

        for connector in self.connectors:
            snapshot = await self._connect(connector)
            if snapshot is None:
                continue

            servers_scanned += 1
            findings = await self._scan_server(snapshot)
            all_findings.extend(findings)

            # Calculate per-server score
            # Count unique checks that ran (by check_id)
            check_ids_run = {f.check_id for f in findings if f.status != Status.SKIPPED}
            server_score = calculate_server_score(findings, len(check_ids_run))
            server_scores.append(server_score)

        duration = time.monotonic() - start_time
        aggregate = calculate_aggregate_score(server_scores)

        return ScanResult(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc),
            medusa_version=__version__,
            scan_duration_seconds=round(duration, 2),
            servers_scanned=servers_scanned,
            total_findings=sum(1 for f in all_findings if f.status == Status.FAIL),
            findings=all_findings,
            server_scores=server_scores,
            aggregate_score=aggregate,
            aggregate_grade=score_to_grade(aggregate),
        )


def has_findings_above_threshold(
    result: ScanResult, threshold: str
) -> bool:
    """Check if any findings meet or exceed the given severity threshold."""
    severity_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0,
    }
    threshold_level = severity_order.get(threshold.lower(), 3)

    for finding in result.findings:
        if finding.status == Status.FAIL:
            finding_level = severity_order.get(finding.severity.value, 0)
            if finding_level >= threshold_level:
                return True
    return False
