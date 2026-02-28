"""Scan engine that orchestrates the full Medusa scan workflow."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from medusa import __version__
from medusa.connectors.base import BaseConnector
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.exceptions import ConnectionError
from medusa.core.models import Finding, ScanResult, Status
from medusa.core.registry import CheckRegistry
from medusa.core.scoring import (
    calculate_aggregate_score,
    calculate_server_score,
    score_to_grade,
)

logger = logging.getLogger(__name__)

# Type alias for progress callbacks.
# Called as callback(event, detail) where event is one of:
#   "server_start"  — detail = server connector name
#   "server_done"   — detail = server connector name
#   "check_done"    — detail = check_id
ProgressCallback = Callable[[str, str], None]


class ScanEngine:
    """Orchestrates the full scan: connect -> snapshot -> check -> score.

    Supports parallel scanning of servers and checks via *max_concurrency*.
    An optional *progress_callback* receives ``(event, detail)`` tuples so
    the CLI can update a progress bar without coupling the engine to Rich.
    """

    def __init__(
        self,
        connectors: list[BaseConnector],
        registry: CheckRegistry,
        categories: list[str] | None = None,
        severities: list[str] | None = None,
        check_ids: list[str] | None = None,
        exclude_ids: list[str] | None = None,
        max_concurrency: int = 4,
        progress_callback: ProgressCallback | None = None,
        ai_enabled: bool = False,
    ) -> None:
        self.connectors = connectors
        self.registry = registry
        self.ai_enabled = ai_enabled

        all_checks = registry.get_checks(
            categories=categories,
            severities=severities,
            check_ids=check_ids,
            exclude_ids=exclude_ids,
        )
        # Filter out AI checks unless explicitly enabled
        if ai_enabled:
            self.checks = all_checks
        else:
            self.checks = [
                c
                for c in all_checks
                if not c.metadata().check_id.startswith("ai")
            ]
        self.max_concurrency = max_concurrency
        self.progress_callback = progress_callback

    def _emit(self, event: str, detail: str) -> None:
        """Fire progress callback if one is registered."""
        if self.progress_callback is not None:
            self.progress_callback(event, detail)

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

    async def _run_check(self, check: BaseCheck, snapshot: ServerSnapshot) -> list[Finding]:
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
        """Run all checks concurrently against a single server snapshot.

        Checks operate on an immutable *ServerSnapshot* with no shared
        mutable state, so it is safe to run them in parallel.
        """
        tasks = [self._run_check(check, snapshot) for check in self.checks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: list[Finding] = []
        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                meta = self.checks[i].metadata()
                logger.error(
                    "Unexpected error in check %s on '%s': %s",
                    meta.check_id,
                    snapshot.server_name,
                    result,
                )
                all_findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.ERROR,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="server",
                        resource_name=snapshot.server_name,
                        status_extended=(f"Check execution error: {result}"),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )
            else:
                all_findings.extend(result)
            self._emit("check_done", self.checks[i].metadata().check_id)
        return all_findings

    async def _scan_one(
        self,
        connector: BaseConnector,
        semaphore: asyncio.Semaphore,
    ) -> tuple[list[Finding], object | None]:
        """Connect + scan a single server, guarded by a semaphore."""
        async with semaphore:
            self._emit("server_start", connector.name)
            snapshot = await self._connect(connector)
            if snapshot is None:
                # Emit check_done for each check so the progress bar
                # still advances even when connection fails.
                for check in self.checks:
                    self._emit("check_done", check.metadata().check_id)
                self._emit("server_done", connector.name)
                return [], None

            findings = await self._scan_server(snapshot)

            check_ids_run = {f.check_id for f in findings if f.status != Status.SKIPPED}
            server_score = calculate_server_score(findings, len(check_ids_run))
            self._emit("server_done", connector.name)
            return findings, server_score

    async def scan(self) -> ScanResult:
        """Execute the full scan across all configured servers.

        Servers are scanned concurrently up to *max_concurrency*.
        Within each server all checks run concurrently as well.
        """
        start_time = time.monotonic()
        scan_id = str(uuid.uuid4())[:8]

        semaphore = asyncio.Semaphore(self.max_concurrency)
        raw_results = await asyncio.gather(
            *[self._scan_one(c, semaphore) for c in self.connectors],
            return_exceptions=True,
        )

        all_findings: list[Finding] = []
        server_scores = []
        servers_scanned = 0

        for result in raw_results:
            if isinstance(result, BaseException):
                logger.error("Server scan raised: %s", result)
                continue
            findings, score = result
            if score is None:
                continue
            servers_scanned += 1
            all_findings.extend(findings)
            server_scores.append(score)

        duration = time.monotonic() - start_time
        aggregate = calculate_aggregate_score(server_scores)

        return ScanResult(
            scan_id=scan_id,
            timestamp=datetime.now(UTC),
            medusa_version=__version__,
            scan_duration_seconds=round(duration, 2),
            servers_scanned=servers_scanned,
            total_findings=sum(1 for f in all_findings if f.status == Status.FAIL),
            findings=all_findings,
            server_scores=server_scores,
            aggregate_score=aggregate,
            aggregate_grade=score_to_grade(aggregate),
        )


def has_findings_above_threshold(result: ScanResult, threshold: str) -> bool:
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
