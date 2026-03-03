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
from medusa.core.models import Finding, ScanResult, Severity, Status
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
        scan_mode: str = "static",
        enable_reasoning: bool = False,
    ) -> None:
        self.connectors = connectors
        self.registry = registry
        self.scan_mode = scan_mode
        self.enable_reasoning = enable_reasoning
        self._reasoning_results: dict[str, object] = {}
        self._filter_stats: dict[str, dict[str, int]] = {}
        self._server_tools: dict[str, list[dict]] = {}  # for change tracking

        all_checks = registry.get_checks(
            categories=categories,
            severities=severities,
            check_ids=check_ids,
            exclude_ids=exclude_ids,
        )
        # Filter checks based on scan mode
        if scan_mode == "ai":
            self.checks = [c for c in all_checks if c.metadata().check_id.startswith("ai")]
        elif scan_mode == "full":
            self.checks = all_checks
        else:  # "static" (default)
            self.checks = [c for c in all_checks if not c.metadata().check_id.startswith("ai")]
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
        mutable state, so it is safe to run them in parallel.  AI checks
        are throttled via a global semaphore configured from snapshot size.
        """
        # Configure AI throttle if this scan includes AI checks
        if self.scan_mode in ("ai", "full"):
            from medusa.ai.throttle import configure_throttle

            configure_throttle(snapshot)

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

            # Store tools for change tracking
            self._server_tools[snapshot.server_name] = list(snapshot.tools)

            findings = await self._scan_server(snapshot)

            # Phase 2: AI Reasoning (post-process static findings)
            if self.enable_reasoning:
                reasoning_result = await self._run_reasoning(snapshot, findings)
                if reasoning_result is not None:
                    self._reasoning_results[snapshot.server_name] = reasoning_result
                    # Apply AI reasoning: filter FPs, adjust severities,
                    # add gap findings — all invisibly.
                    findings, filter_stats = self._apply_reasoning_to_findings(
                        findings, reasoning_result, snapshot
                    )
                    self._filter_stats[snapshot.server_name] = filter_stats
                self._emit("check_done", "ai_reasoning")

            check_ids_run = {
                f.check_id
                for f in findings
                if f.status != Status.SKIPPED and f.severity != Severity.INFORMATIONAL
            }
            server_score = calculate_server_score(findings, len(check_ids_run))
            self._emit("server_done", connector.name)
            return findings, server_score

    async def _run_reasoning(
        self,
        snapshot: ServerSnapshot,
        findings: list[Finding],
    ) -> object | None:
        """Run the AI reasoning engine over static findings.

        Returns a ReasoningResult on success, or None on failure.
        """
        try:
            from medusa.ai.client import get_client
            from medusa.ai.reasoning.engine import ReasoningEngine

            client = get_client()
            engine = ReasoningEngine(client=client)
            return await engine.reason(snapshot, findings)
        except Exception:
            logger.exception(
                "AI reasoning failed for '%s'",
                snapshot.server_name,
            )
            return None

    def _apply_reasoning_to_findings(
        self,
        findings: list[Finding],
        reasoning_result: object,
        snapshot: ServerSnapshot,
    ) -> tuple[list[Finding], dict[str, int]]:
        """Apply AI reasoning to silently improve finding accuracy.

        - Removes false positives (confidence_score < 0.3, double-gated)
        - Never removes CRITICAL severity findings
        - Adjusts severities when AI provides adjusted_severity
        - Adds gap findings as normal findings
        - Caps bulk removal at 50% as a safety valve

        Returns the filtered findings and a stats dict.
        """
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFORMATIONAL,
        }

        annotations = getattr(reasoning_result, "annotations", [])
        stats: dict[str, int] = {
            "false_positives_removed": 0,
            "severities_adjusted": 0,
            "gaps_added": 0,
            "critical_preserved": 0,
        }

        # Build lookup: (check_id, resource_name) -> annotation
        annotation_map: dict[tuple[str, str], object] = {}
        for ann in annotations:
            key = (ann.check_id, ann.resource_name)
            annotation_map[key] = ann

        # Count FAIL findings before filtering (for bulk safety valve)
        fail_count_before = sum(1 for f in findings if f.status == Status.FAIL)
        removal_candidates: list[int] = []  # indices to remove

        filtered: list[Finding] = []
        for idx, f in enumerate(findings):
            key = (f.check_id, f.resource_name)
            ann = annotation_map.get(key)

            if ann and f.status == Status.FAIL:
                conf = getattr(ann, "confidence", "")
                conf_score = getattr(ann, "confidence_score", 1.0)

                # Filter false positives: double-gate
                if conf in ("false_positive", "likely_false_positive") and conf_score < 0.3:
                    if f.severity == Severity.CRITICAL:
                        # Never auto-remove critical findings
                        stats["critical_preserved"] += 1
                    else:
                        removal_candidates.append(idx)
                        continue  # tentatively skip

                # Adjust severity if AI provides one
                adj_sev_str = getattr(ann, "adjusted_severity", None)
                if adj_sev_str:
                    new_sev = severity_map.get(adj_sev_str.lower())
                    if new_sev and new_sev != f.severity:
                        f = f.model_copy(update={"severity": new_sev})
                        stats["severities_adjusted"] += 1

            filtered.append(f)

        # Bulk safety valve: if >50% of FAIL findings removed, skip all
        if fail_count_before > 0:
            removal_ratio = len(removal_candidates) / fail_count_before
            if removal_ratio > 0.5:
                logger.warning(
                    "AI tried to remove %.0f%% of findings for '%s' "
                    "— skipping all filtering as a safety measure",
                    removal_ratio * 100,
                    snapshot.server_name,
                )
                # Reset: return original findings, no removals
                filtered = list(findings)
                stats["false_positives_removed"] = 0
                stats["severities_adjusted"] = 0
            else:
                stats["false_positives_removed"] = len(removal_candidates)

        # Add gap findings with normalized IDs (no AI branding)
        gap_findings = self._gaps_to_findings(reasoning_result, snapshot)
        filtered.extend(gap_findings)
        stats["gaps_added"] = len(gap_findings)

        return filtered, stats

    def _gaps_to_findings(
        self,
        reasoning_result: object,
        snapshot: ServerSnapshot,
    ) -> list[Finding]:
        """Convert AI-discovered gap findings into standard Findings.

        Gap findings are indistinguishable from static findings in the
        output — no AI labels, no special prefixes.
        """
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFORMATIONAL,
        }

        result: list[Finding] = []
        gap_findings = getattr(reasoning_result, "gap_findings", [])
        for i, gap in enumerate(gap_findings):
            result.append(
                Finding(
                    check_id=f"gap{i + 1:03d}",
                    check_title=gap.title,
                    status=Status.FAIL,
                    severity=severity_map.get(gap.severity.lower(), Severity.MEDIUM),
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type=gap.resource_type,
                    resource_name=gap.resource_name,
                    status_extended=gap.description,
                    evidence=gap.evidence,
                    remediation=gap.remediation,
                    owasp_mcp=gap.owasp_mcp,
                )
            )
        return result

    async def scan(self) -> ScanResult:
        """Execute the full scan across all configured servers.

        Servers are scanned concurrently up to *max_concurrency*.
        Within each server all checks run concurrently as well.
        AI checks are throttled via a dynamic semaphore.
        """
        start_time = time.monotonic()
        scan_id = str(uuid.uuid4())[:8]

        # Reset AI throttle for a fresh scan
        if self.scan_mode in ("ai", "full"):
            from medusa.ai.throttle import reset_throttle

            reset_throttle()

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

        # Serialize reasoning results if present
        reasoning_results: dict = {}
        if self.enable_reasoning and self._reasoning_results:
            for name, r in self._reasoning_results.items():
                try:
                    reasoning_results[name] = r.model_dump(mode="json")
                except Exception:
                    logger.warning(
                        "Failed to serialize reasoning for '%s'",
                        name,
                    )

        # Change detection: compare against previous scan
        changes: dict[str, list[dict]] = {}
        if self._server_tools:
            try:
                from medusa.core.change_tracker import detect_changes, save_snapshot

                changes = detect_changes(self._server_tools)
                save_snapshot(self._server_tools)
            except Exception:
                logger.debug("Change tracking unavailable", exc_info=True)

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
            reasoning_results=reasoning_results,
            ai_filter_stats=self._filter_stats,
            changes=changes,
        )


def has_findings_above_threshold(result: ScanResult, threshold: str) -> bool:
    """Check if any findings meet or exceed the given severity threshold."""
    severity_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }
    threshold_level = severity_order.get(threshold.lower(), 3)

    for finding in result.findings:
        if finding.status == Status.FAIL:
            finding_level = severity_order.get(finding.severity.value, 0)
            if finding_level >= threshold_level:
                return True
    return False
