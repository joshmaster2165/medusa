"""Benchmark runner that uses the existing ScanEngine to scan catalog servers."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import yaml

from medusa.benchmarks.models import (
    BenchmarkReport,
    BenchmarkServerResult,
    ServerCatalogEntry,
)


def load_server_catalog() -> list[ServerCatalogEntry]:
    """Load the built-in server catalog."""
    catalog_path = Path(__file__).parent / "servers.yaml"
    data = yaml.safe_load(catalog_path.read_text())
    return [ServerCatalogEntry(**s) for s in data.get("servers", [])]


def filter_catalog(
    catalog: list[ServerCatalogEntry],
    server_names: list[str] | None = None,
) -> list[ServerCatalogEntry]:
    """Filter catalog to specific servers if requested."""
    if not server_names:
        return catalog
    name_set = {n.lower() for n in server_names}
    return [s for s in catalog if s.name.lower() in name_set]


def check_env_requirements(entry: ServerCatalogEntry) -> tuple[bool, str]:
    """Check if required environment variables are set."""
    missing = [v for v in entry.env_required if not os.environ.get(v)]
    if missing:
        return False, f"Missing env vars: {', '.join(missing)}"
    return True, ""


async def run_benchmark(
    server_names: list[str] | None = None,
    timeout: int = 60,
) -> BenchmarkReport:
    """Run benchmarks against catalog servers.

    Does NOT auto-install npm packages. Skips servers with missing env vars.
    Uses the existing ScanEngine and StdioConnector.
    """
    from medusa import __version__
    from medusa.connectors.stdio import StdioConnector
    from medusa.core.models import Severity, Status
    from medusa.core.registry import CheckRegistry
    from medusa.core.scanner import ScanEngine

    catalog = load_server_catalog()
    catalog = filter_catalog(catalog, server_names)

    results: list[BenchmarkServerResult] = []
    scanned = 0
    skipped = 0

    for entry in catalog:
        # Check env requirements
        env_ok, reason = check_env_requirements(entry)
        if not env_ok:
            results.append(
                BenchmarkServerResult(
                    server_name=entry.name,
                    package=entry.package,
                    status="skipped",
                    skip_reason=reason,
                )
            )
            skipped += 1
            continue

        try:
            # Build a StdioConnector for this server
            env_vars = {v: os.environ.get(v, "") for v in entry.env_required}
            connector = StdioConnector(
                name=entry.name,
                command=entry.command,
                args=entry.args,
                env=env_vars if env_vars else None,
            )

            # Build registry and engine for this single server
            registry = CheckRegistry()
            registry.discover_checks()

            engine = ScanEngine(
                connectors=[connector],
                registry=registry,
                scan_mode="static",
            )

            report = await engine.scan()

            # Extract results from scan report
            findings = report.findings
            total = len(findings)
            passed = sum(1 for f in findings if f.status == Status.PASS)
            failed = total - passed
            critical = sum(
                1 for f in findings
                if f.status == Status.FAIL and f.severity == Severity.CRITICAL
            )
            high = sum(
                1 for f in findings
                if f.status == Status.FAIL and f.severity == Severity.HIGH
            )
            medium = sum(
                1 for f in findings
                if f.status == Status.FAIL and f.severity == Severity.MEDIUM
            )
            low = sum(
                1 for f in findings
                if f.status == Status.FAIL and f.severity == Severity.LOW
            )
            info = sum(
                1 for f in findings
                if f.status == Status.FAIL and f.severity == Severity.INFORMATIONAL
            )

            # Get unique failing categories
            categories_failed = sorted(set(
                f.check_id.rsplit("0", 1)[0] if "0" in f.check_id else f.check_id
                for f in findings
                if f.status == Status.FAIL
            ))[:10]

            # Top findings by severity
            severity_order = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
                Severity.INFORMATIONAL: 4,
            }
            top = [
                f"{f.check_id}: {f.check_title}"
                for f in sorted(
                    [f for f in findings if f.status == Status.FAIL],
                    key=lambda x: severity_order.get(x.severity, 4),
                )[:5]
            ]

            # Extract counts from server scores if available
            tool_count = 0
            resource_count = 0
            prompt_count = 0
            score = report.aggregate_score
            grade = report.aggregate_grade

            results.append(
                BenchmarkServerResult(
                    server_name=entry.name,
                    package=entry.package,
                    status="scanned",
                    score=score,
                    grade=grade,
                    total_checks=total,
                    passed=passed,
                    failed=failed,
                    critical_findings=critical,
                    high_findings=high,
                    medium_findings=medium,
                    low_findings=low,
                    info_findings=info,
                    tool_count=tool_count,
                    resource_count=resource_count,
                    prompt_count=prompt_count,
                    categories_failed=categories_failed,
                    top_findings=top,
                )
            )
            scanned += 1

        except Exception as exc:
            results.append(
                BenchmarkServerResult(
                    server_name=entry.name,
                    package=entry.package,
                    status="error",
                    error_message=str(exc)[:200],
                )
            )
            skipped += 1

    # Calculate average score across scanned servers
    scanned_results = [r for r in results if r.status == "scanned"]
    avg_score = (
        sum(r.score for r in scanned_results) / len(scanned_results)
        if scanned_results
        else 0.0
    )

    return BenchmarkReport(
        timestamp=datetime.now(timezone.utc).isoformat(),
        medusa_version=__version__,
        total_servers=len(catalog),
        scanned_servers=scanned,
        skipped_servers=skipped,
        average_score=round(avg_score, 1),
        results=results,
    )
