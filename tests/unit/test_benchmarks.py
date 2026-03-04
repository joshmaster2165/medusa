"""Unit tests for the Medusa Benchmark Suite."""

from __future__ import annotations

from medusa.benchmarks.models import (
    BenchmarkReport,
    BenchmarkServerResult,
    BenchmarkToolResult,
    ServerCatalogEntry,
)
from medusa.benchmarks.report import generate_markdown_report
from medusa.benchmarks.runner import (
    check_env_requirements,
    filter_catalog,
    load_server_catalog,
)

# ==========================================================================
# Model Tests
# ==========================================================================


class TestServerCatalogEntry:
    """Tests for the ServerCatalogEntry model."""

    def test_basic_creation(self) -> None:
        """Minimal entry should have sensible defaults."""
        e = ServerCatalogEntry(name="test", package="@test/server")
        assert e.name == "test"
        assert e.package == "@test/server"
        assert e.transport == "stdio"
        assert e.command == "npx"
        assert e.env_required == []
        assert e.args == []
        assert e.description == ""
        assert e.category == ""
        assert e.url == ""

    def test_with_env_required(self) -> None:
        """Entry with env_required should retain the list."""
        e = ServerCatalogEntry(
            name="github",
            package="@mcp/server-github",
            env_required=["GITHUB_TOKEN"],
        )
        assert len(e.env_required) == 1
        assert e.env_required[0] == "GITHUB_TOKEN"

    def test_with_all_fields(self) -> None:
        """Entry with all fields populated should retain them."""
        e = ServerCatalogEntry(
            name="full",
            package="@test/full-server",
            transport="http",
            command="node",
            args=["index.js", "--port", "3000"],
            env_required=["API_KEY", "DB_URL"],
            description="A full server entry",
            category="Testing",
            url="https://example.com",
        )
        assert e.transport == "http"
        assert e.command == "node"
        assert len(e.args) == 3
        assert len(e.env_required) == 2
        assert e.description == "A full server entry"
        assert e.category == "Testing"


class TestBenchmarkToolResult:
    """Tests for the BenchmarkToolResult model."""

    def test_basic_creation(self) -> None:
        """Tool result with only name should have zero defaults."""
        r = BenchmarkToolResult(tool_name="get_weather")
        assert r.tool_name == "get_weather"
        assert r.total_checks == 0
        assert r.passed == 0
        assert r.failed == 0
        assert r.critical_findings == 0
        assert r.high_findings == 0

    def test_with_values(self) -> None:
        """Tool result with populated fields."""
        r = BenchmarkToolResult(
            tool_name="delete_user",
            total_checks=20,
            passed=15,
            failed=5,
            critical_findings=1,
            high_findings=2,
        )
        assert r.failed == 5
        assert r.critical_findings == 1


class TestBenchmarkServerResult:
    """Tests for the BenchmarkServerResult model."""

    def test_scanned_result(self) -> None:
        """Scanned result with score and grade."""
        r = BenchmarkServerResult(
            server_name="test",
            package="@test/server",
            status="scanned",
            score=8.5,
            grade="B",
            total_checks=100,
            passed=90,
            failed=10,
        )
        assert r.status == "scanned"
        assert r.score == 8.5
        assert r.grade == "B"
        assert r.total_checks == 100
        assert r.passed == 90
        assert r.failed == 10

    def test_skipped_result(self) -> None:
        """Skipped result with reason."""
        r = BenchmarkServerResult(
            server_name="test",
            package="@test/server",
            status="skipped",
            skip_reason="Missing env vars: GITHUB_TOKEN",
        )
        assert r.status == "skipped"
        assert "GITHUB_TOKEN" in r.skip_reason
        assert r.score == 0.0

    def test_error_result(self) -> None:
        """Error result with message."""
        r = BenchmarkServerResult(
            server_name="test",
            package="@test/server",
            status="error",
            error_message="Connection refused",
        )
        assert r.status == "error"
        assert "Connection refused" in r.error_message

    def test_defaults(self) -> None:
        """Default values for optional fields."""
        r = BenchmarkServerResult(
            server_name="test",
            package="@test/server",
            status="scanned",
        )
        assert r.skip_reason == ""
        assert r.error_message == ""
        assert r.score == 0.0
        assert r.grade == ""
        assert r.categories_failed == []
        assert r.top_findings == []


class TestBenchmarkReport:
    """Tests for the BenchmarkReport model."""

    def test_empty_report(self) -> None:
        """Empty report should have zero counts and no results."""
        r = BenchmarkReport(timestamp="2025-01-01T00:00:00Z")
        assert r.total_servers == 0
        assert r.scanned_servers == 0
        assert r.skipped_servers == 0
        assert r.average_score == 0.0
        assert r.results == []

    def test_report_with_results(self) -> None:
        """Report with mixed scanned and skipped results."""
        r = BenchmarkReport(
            timestamp="2025-01-01T00:00:00Z",
            total_servers=2,
            scanned_servers=1,
            skipped_servers=1,
            average_score=7.5,
            results=[
                BenchmarkServerResult(
                    server_name="test1",
                    package="@test/s1",
                    status="scanned",
                    score=7.5,
                    grade="B",
                ),
                BenchmarkServerResult(
                    server_name="test2",
                    package="@test/s2",
                    status="skipped",
                    skip_reason="Missing env",
                ),
            ],
        )
        assert len(r.results) == 2
        assert r.total_servers == 2
        assert r.scanned_servers == 1
        assert r.skipped_servers == 1

    def test_report_with_version(self) -> None:
        """Report with Medusa version set."""
        r = BenchmarkReport(
            timestamp="2025-01-01T00:00:00Z",
            medusa_version="0.5.0",
        )
        assert r.medusa_version == "0.5.0"


# ==========================================================================
# Catalog Tests
# ==========================================================================


class TestServerCatalog:
    """Tests for loading and filtering the server catalog."""

    def test_load_catalog(self) -> None:
        """Should load the built-in catalog with known servers."""
        catalog = load_server_catalog()
        assert len(catalog) == 9
        names = [s.name for s in catalog]
        assert "filesystem" in names
        assert "memory" in names
        assert "everything" in names
        assert "github" in names
        assert "sequential-thinking" in names

    def test_all_entries_have_package(self) -> None:
        """Every catalog entry should have a package containing '@'."""
        for entry in load_server_catalog():
            assert entry.package, f"{entry.name} missing package"
            assert "@" in entry.package, f"{entry.name} package should contain @"

    def test_all_entries_have_name(self) -> None:
        """Every catalog entry should have a non-empty name."""
        for entry in load_server_catalog():
            assert entry.name

    def test_filter_by_name(self) -> None:
        """Filtering by specific server names."""
        catalog = load_server_catalog()
        filtered = filter_catalog(catalog, ["filesystem", "memory"])
        assert len(filtered) == 2
        assert {s.name for s in filtered} == {"filesystem", "memory"}

    def test_filter_by_single_name(self) -> None:
        """Filtering to a single server."""
        catalog = load_server_catalog()
        filtered = filter_catalog(catalog, ["everything"])
        assert len(filtered) == 1
        assert filtered[0].name == "everything"

    def test_filter_none_returns_all(self) -> None:
        """None filter should return all servers."""
        catalog = load_server_catalog()
        filtered = filter_catalog(catalog, None)
        assert len(filtered) == len(catalog)

    def test_filter_empty_list_returns_all(self) -> None:
        """Empty list filter should return all servers."""
        catalog = load_server_catalog()
        filtered = filter_catalog(catalog, [])
        assert len(filtered) == len(catalog)

    def test_filter_nonexistent_name(self) -> None:
        """Filtering by a non-existent name should return empty list."""
        catalog = load_server_catalog()
        filtered = filter_catalog(catalog, ["nonexistent_server_xyz"])
        assert len(filtered) == 0

    def test_env_requirements_missing(self) -> None:
        """Entry with missing env vars should fail the check."""
        entry = ServerCatalogEntry(
            name="test",
            package="@test/s",
            env_required=["NONEXISTENT_VAR_12345"],
        )
        ok, reason = check_env_requirements(entry)
        assert not ok
        assert "NONEXISTENT_VAR_12345" in reason

    def test_env_requirements_none_needed(self) -> None:
        """Entry with no env_required should pass."""
        entry = ServerCatalogEntry(name="test", package="@test/s")
        ok, reason = check_env_requirements(entry)
        assert ok
        assert reason == ""

    def test_env_requirements_multiple_missing(self) -> None:
        """Entry with multiple missing env vars should list them all."""
        entry = ServerCatalogEntry(
            name="test",
            package="@test/s",
            env_required=["MISSING_VAR_A_12345", "MISSING_VAR_B_12345"],
        )
        ok, reason = check_env_requirements(entry)
        assert not ok
        assert "MISSING_VAR_A_12345" in reason
        assert "MISSING_VAR_B_12345" in reason

    def test_servers_with_env_requirements(self) -> None:
        """Servers requiring env vars should list them correctly."""
        catalog = load_server_catalog()
        github = next((s for s in catalog if s.name == "github"), None)
        assert github is not None
        assert len(github.env_required) >= 1
        assert "GITHUB_PERSONAL_ACCESS_TOKEN" in github.env_required


# ==========================================================================
# Markdown Report Tests
# ==========================================================================


class TestMarkdownReport:
    """Tests for Markdown report generation."""

    def test_generate_markdown(self) -> None:
        """Should generate a valid Markdown report with server data."""
        report = BenchmarkReport(
            timestamp="2025-01-01T00:00:00Z",
            total_servers=1,
            scanned_servers=1,
            average_score=8.0,
            results=[
                BenchmarkServerResult(
                    server_name="test",
                    package="@test/server",
                    status="scanned",
                    score=8.0,
                    grade="B",
                    tool_count=5,
                    passed=90,
                    failed=10,
                    critical_findings=0,
                    high_findings=2,
                ),
            ],
        )
        md = generate_markdown_report(report)
        assert "# Medusa Benchmark Report" in md
        assert "test" in md
        assert "8.0" in md
        assert "@test/server" in md
        assert "scanned" in md

    def test_markdown_with_skipped(self) -> None:
        """Should include skipped server details in Markdown."""
        report = BenchmarkReport(
            timestamp="2025-01-01T00:00:00Z",
            total_servers=1,
            skipped_servers=1,
            results=[
                BenchmarkServerResult(
                    server_name="github",
                    package="@mcp/github",
                    status="skipped",
                    skip_reason="Missing GITHUB_TOKEN",
                ),
            ],
        )
        md = generate_markdown_report(report)
        assert "skipped" in md
        assert "GITHUB_TOKEN" in md
        assert "github" in md

    def test_markdown_with_error(self) -> None:
        """Should include error server details in Markdown."""
        report = BenchmarkReport(
            timestamp="2025-01-01T00:00:00Z",
            total_servers=1,
            results=[
                BenchmarkServerResult(
                    server_name="broken",
                    package="@test/broken",
                    status="error",
                    error_message="Connection timed out",
                ),
            ],
        )
        md = generate_markdown_report(report)
        assert "error" in md
        assert "Connection timed out" in md

    def test_markdown_with_top_findings(self) -> None:
        """Should include top findings section for scanned servers."""
        report = BenchmarkReport(
            timestamp="2025-01-01T00:00:00Z",
            total_servers=1,
            scanned_servers=1,
            results=[
                BenchmarkServerResult(
                    server_name="test",
                    package="@test/server",
                    status="scanned",
                    score=5.0,
                    grade="D",
                    top_findings=["tp001: Hidden Instructions", "iv001: Command Injection"],
                ),
            ],
        )
        md = generate_markdown_report(report)
        assert "Top Findings" in md
        assert "tp001" in md
        assert "iv001" in md

    def test_markdown_contains_table_header(self) -> None:
        """Markdown should contain the results table header."""
        report = BenchmarkReport(
            timestamp="2025-01-01T00:00:00Z",
            total_servers=0,
        )
        md = generate_markdown_report(report)
        assert "| Server |" in md
        assert "| Package |" in md

    def test_markdown_mixed_results(self) -> None:
        """Markdown with scanned, skipped, and error results."""
        report = BenchmarkReport(
            timestamp="2025-01-01T00:00:00Z",
            total_servers=3,
            scanned_servers=1,
            skipped_servers=1,
            average_score=6.0,
            results=[
                BenchmarkServerResult(
                    server_name="good",
                    package="@test/good",
                    status="scanned",
                    score=6.0,
                    grade="C",
                ),
                BenchmarkServerResult(
                    server_name="missing-env",
                    package="@test/skip",
                    status="skipped",
                    skip_reason="Missing API_KEY",
                ),
                BenchmarkServerResult(
                    server_name="broken",
                    package="@test/broken",
                    status="error",
                    error_message="Timeout",
                ),
            ],
        )
        md = generate_markdown_report(report)
        assert "good" in md
        assert "missing-env" in md
        assert "broken" in md
        assert "6.0" in md
