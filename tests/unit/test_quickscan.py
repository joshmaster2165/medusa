"""Tests for the medusa quickscan CLI command."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner

from medusa.cli.main import cli
from medusa.connectors.stdio import StdioConnector
from medusa.core.models import ScanResult, ServerScore


def _mock_scan_result(**overrides):
    """Create a minimal ScanResult for testing."""
    defaults = {
        "scan_id": "test-abc",
        "timestamp": "2025-01-01T00:00:00Z",
        "medusa_version": "0.1.0",
        "scan_duration_seconds": 1.5,
        "servers_scanned": 1,
        "total_findings": 0,
        "findings": [],
        "server_scores": [
            ServerScore(
                server_name="test-server",
                score=9.0,
                grade="A",
                total_checks=100,
                passed=100,
                failed=0,
                critical_findings=0,
                high_findings=0,
                medium_findings=0,
                low_findings=0,
            )
        ],
        "aggregate_score": 9.0,
        "aggregate_grade": "A",
    }
    defaults.update(overrides)
    return ScanResult(**defaults)


class TestQuickscanCommand:
    """Test the quickscan CLI command."""

    def test_quickscan_no_servers_exits_3(self):
        """If no servers found, exit with code 3."""
        runner = CliRunner()
        with patch("medusa.cli.main.discover_servers_detailed", return_value={}):
            result = runner.invoke(cli, ["quickscan"])
            assert result.exit_code == 3
            assert "No MCP servers found" in result.output

    def test_quickscan_no_servers_shows_checked_locations(self):
        """The 'no servers' message lists checked locations."""
        runner = CliRunner()
        with patch("medusa.cli.main.discover_servers_detailed", return_value={}):
            result = runner.invoke(cli, ["quickscan"])
            assert "Claude Desktop" in result.output
            assert "Cursor" in result.output
            assert "Roo Code" in result.output
            assert "GitHub Copilot" in result.output
            assert "medusa scan --stdio" in result.output

    def test_quickscan_discovers_servers(self):
        """Quickscan shows discovery summary with server names."""
        mock_connector = MagicMock(spec=StdioConnector)
        mock_connector.name = "test-server"

        grouped = {"Claude Desktop": [mock_connector]}

        mock_result = _mock_scan_result()

        with (
            patch(
                "medusa.cli.main.discover_servers_detailed",
                return_value=grouped,
            ),
            patch("medusa.cli.main.ScanEngine") as mock_engine_cls,
        ):
            engine_instance = MagicMock()
            engine_instance.checks = [MagicMock() for _ in range(10)]
            engine_instance.scan = AsyncMock(return_value=mock_result)
            mock_engine_cls.return_value = engine_instance

            runner = CliRunner()
            result = runner.invoke(cli, ["quickscan"])
            # Should show discovery info
            assert "Claude Desktop" in result.output
            assert "test-server" in result.output

    def test_quickscan_quiet_mode(self):
        """Quiet mode suppresses output."""
        runner = CliRunner()
        with patch("medusa.cli.main.discover_servers_detailed", return_value={}):
            result = runner.invoke(cli, ["-q", "quickscan"])
            assert result.exit_code == 3
            # Quiet mode: no output except errors
            assert "No MCP servers found" not in result.output

    def test_quickscan_json_output(self):
        """JSON output format works."""
        mock_connector = MagicMock(spec=StdioConnector)
        mock_connector.name = "test"

        grouped = {"Cursor": [mock_connector]}
        mock_result = _mock_scan_result()

        with (
            patch(
                "medusa.cli.main.discover_servers_detailed",
                return_value=grouped,
            ),
            patch("medusa.cli.main.ScanEngine") as mock_engine_cls,
        ):
            engine_instance = MagicMock()
            engine_instance.checks = [MagicMock() for _ in range(5)]
            engine_instance.scan = AsyncMock(return_value=mock_result)
            mock_engine_cls.return_value = engine_instance

            runner = CliRunner()
            result = runner.invoke(cli, ["quickscan", "-o", "json"])
            # Should contain valid JSON in output (ScanResult dump)
            assert result.exit_code == 0

    def test_quickscan_output_file(self, tmp_path):
        """--output-file writes report to disk."""
        mock_connector = MagicMock(spec=StdioConnector)
        mock_connector.name = "test"

        grouped = {"VS Code": [mock_connector]}
        mock_result = _mock_scan_result()
        out_file = str(tmp_path / "report.json")

        with (
            patch(
                "medusa.cli.main.discover_servers_detailed",
                return_value=grouped,
            ),
            patch("medusa.cli.main.ScanEngine") as mock_engine_cls,
        ):
            engine_instance = MagicMock()
            engine_instance.checks = [MagicMock() for _ in range(5)]
            engine_instance.scan = AsyncMock(return_value=mock_result)
            mock_engine_cls.return_value = engine_instance

            runner = CliRunner()
            result = runner.invoke(
                cli,
                ["quickscan", "-o", "json", "--output-file", out_file],
            )
            assert result.exit_code == 0
            assert "Report saved" in result.output

    def test_quickscan_severity_filter(self):
        """--severity flag is passed to ScanEngine."""
        mock_connector = MagicMock(spec=StdioConnector)
        mock_connector.name = "test"

        grouped = {"Cursor": [mock_connector]}
        mock_result = _mock_scan_result()

        with (
            patch(
                "medusa.cli.main.discover_servers_detailed",
                return_value=grouped,
            ),
            patch("medusa.cli.main.ScanEngine") as mock_engine_cls,
        ):
            engine_instance = MagicMock()
            engine_instance.checks = [MagicMock() for _ in range(5)]
            engine_instance.scan = AsyncMock(return_value=mock_result)
            mock_engine_cls.return_value = engine_instance

            runner = CliRunner()
            runner.invoke(cli, ["quickscan", "--severity", "high"])
            # Verify ScanEngine was called with severities filter
            call_kwargs = mock_engine_cls.call_args[1]
            assert call_kwargs["severities"] == ["high"]

    def test_quickscan_help(self):
        """--help shows command documentation."""
        runner = CliRunner()
        result = runner.invoke(cli, ["quickscan", "--help"])
        assert result.exit_code == 0
        assert "Auto-discover and scan ALL MCP servers" in result.output
        assert "Claude Desktop" in result.output
        assert "Roo Code" in result.output
        assert "Continue.dev" in result.output

    def test_quickscan_default_fail_on_critical(self):
        """Default --fail-on is critical (less strict than scan's high)."""
        mock_connector = MagicMock(spec=StdioConnector)
        mock_connector.name = "test"

        grouped = {"Cursor": [mock_connector]}
        # Result with high findings but no critical
        mock_result = _mock_scan_result(
            server_scores=[
                ServerScore(
                    server_name="test",
                    score=5.0,
                    grade="D",
                    total_checks=100,
                    passed=80,
                    failed=20,
                    critical_findings=0,
                    high_findings=5,
                    medium_findings=10,
                    low_findings=5,
                )
            ],
            aggregate_score=5.0,
            aggregate_grade="D",
        )

        with (
            patch(
                "medusa.cli.main.discover_servers_detailed",
                return_value=grouped,
            ),
            patch("medusa.cli.main.ScanEngine") as mock_engine_cls,
            patch(
                "medusa.cli.main.has_findings_above_threshold",
                return_value=False,
            ),
        ):
            engine_instance = MagicMock()
            engine_instance.checks = [MagicMock() for _ in range(5)]
            engine_instance.scan = AsyncMock(return_value=mock_result)
            mock_engine_cls.return_value = engine_instance

            runner = CliRunner()
            result = runner.invoke(cli, ["quickscan"])
            # Should exit 0 because default --fail-on is critical
            # and there are no critical findings
            assert result.exit_code == 0

    def test_quickscan_multiple_clients(self):
        """Multiple clients show in discovery summary."""
        c1 = MagicMock(spec=StdioConnector)
        c1.name = "server-a"
        c2 = MagicMock(spec=StdioConnector)
        c2.name = "server-b"
        c3 = MagicMock(spec=StdioConnector)
        c3.name = "server-c"

        grouped = {
            "Claude Desktop": [c1, c2],
            "Cursor": [c3],
        }
        mock_result = _mock_scan_result()

        with (
            patch(
                "medusa.cli.main.discover_servers_detailed",
                return_value=grouped,
            ),
            patch("medusa.cli.main.ScanEngine") as mock_engine_cls,
        ):
            engine_instance = MagicMock()
            engine_instance.checks = [MagicMock() for _ in range(5)]
            engine_instance.scan = AsyncMock(return_value=mock_result)
            mock_engine_cls.return_value = engine_instance

            runner = CliRunner()
            result = runner.invoke(cli, ["quickscan"])
            assert "3 MCP servers" in result.output
            assert "2 clients" in result.output
            assert "Claude Desktop" in result.output
            assert "Cursor" in result.output
