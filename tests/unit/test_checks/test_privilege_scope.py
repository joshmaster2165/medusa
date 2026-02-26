"""Unit tests for all Privilege & Scope checks (PRIV-001 through PRIV-003).

Each check is tested for:
- FAIL on the vulnerable_snapshot
- PASS on the secure_snapshot
- Graceful handling of the empty_snapshot (no tools)
- Additional edge cases specific to each check
"""

from __future__ import annotations

import pytest

from medusa.checks.privilege_scope.priv001_filesystem_access import FilesystemAccessCheck
from medusa.checks.privilege_scope.priv002_network_access import NetworkAccessCheck
from medusa.checks.privilege_scope.priv003_shell_execution import ShellExecutionCheck
from medusa.core.check import ServerSnapshot
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

# ==========================================================================
# PRIV-001: Overprivileged Filesystem Access
# ==========================================================================


class TestPriv001FilesystemAccess:
    """Tests for FilesystemAccessCheck."""

    @pytest.fixture()
    def check(self) -> FilesystemAccessCheck:
        return FilesystemAccessCheck()

    async def test_metadata_loads_correctly(self, check: FilesystemAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv001"
        assert meta.category == "privilege_scope"
        assert meta.severity == Severity.HIGH

    async def test_fails_on_unrestricted_file_reader(
        self, check: FilesystemAccessCheck, vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        file_reader_findings = [
            f for f in fail_findings if f.resource_name == "file_reader"
        ]
        assert len(file_reader_findings) >= 1, (
            "file_reader with unrestricted path should be flagged"
        )

    async def test_passes_on_secure_snapshot(
        self, check: FilesystemAccessCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        # Secure snapshot has no filesystem tools, so should return empty
        assert len(findings) == 0 or all(
            f.status == Status.PASS for f in findings
        )

    async def test_empty_snapshot_returns_no_findings(
        self, check: FilesystemAccessCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0

    async def test_fs_tool_with_pattern_passes(self, check: FilesystemAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "read_file",
                    "description": "Reads a file.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "pattern": "^/workspace/.*$",
                            },
                        },
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_fs_tool_with_enum_passes(self, check: FilesystemAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "read_file",
                    "description": "Reads a file.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "enum": ["/app/config.json", "/app/data.json"],
                            },
                        },
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_non_fs_tool_is_skipped(self, check: FilesystemAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Gets weather.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "city": {"type": "string"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0, "Non-filesystem tool should not produce findings"

    async def test_fs_tool_with_config_restriction_passes(
        self, check: FilesystemAccessCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "read_file",
                    "description": "Reads a file.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                        },
                    },
                }
            ],
            args=["--allowed-dir", "/workspace"],
        )
        findings = await check.execute(snapshot)
        # With restriction hints in args, should not flag
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0


# ==========================================================================
# PRIV-002: Unrestricted Network Access
# ==========================================================================


class TestPriv002NetworkAccess:
    """Tests for NetworkAccessCheck."""

    @pytest.fixture()
    def check(self) -> NetworkAccessCheck:
        return NetworkAccessCheck()

    async def test_metadata_loads_correctly(self, check: NetworkAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv002"
        assert meta.category == "privilege_scope"
        assert meta.severity == Severity.HIGH

    async def test_no_network_tools_returns_empty(
        self, check: NetworkAccessCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "calculate_sum",
                    "description": "Adds two numbers.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "number"},
                            "b": {"type": "number"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_empty_snapshot_returns_no_findings(
        self, check: NetworkAccessCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0

    async def test_fails_on_unrestricted_fetch_tool(self, check: NetworkAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "http_fetch",
                    "description": "Fetches a URL.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                        },
                        "required": ["url"],
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_with_url_pattern(self, check: NetworkAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "fetch_api",
                    "description": "Calls an API.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "pattern": "^https://api\\.example\\.com/.*$",
                            },
                        },
                        "required": ["url"],
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_with_url_enum(self, check: NetworkAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "download_report",
                    "description": "Downloads a report.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "enum": [
                                    "https://api.example.com/report/daily",
                                    "https://api.example.com/report/weekly",
                                ],
                            },
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_non_network_tool_is_skipped(self, check: NetworkAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "calculate",
                    "description": "Does math.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"a": {"type": "number"}},
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0


# ==========================================================================
# PRIV-003: Shell Execution Capability
# ==========================================================================


class TestPriv003ShellExecution:
    """Tests for ShellExecutionCheck."""

    @pytest.fixture()
    def check(self) -> ShellExecutionCheck:
        return ShellExecutionCheck()

    async def test_metadata_loads_correctly(self, check: ShellExecutionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv003"
        assert meta.category == "privilege_scope"
        assert meta.severity == Severity.CRITICAL

    async def test_fails_on_execute_command_tool(
        self, check: ShellExecutionCheck, vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        exec_findings = [
            f for f in fail_findings if f.resource_name == "execute_command"
        ]
        assert len(exec_findings) >= 1, "execute_command tool should be flagged"

    async def test_passes_on_secure_snapshot(
        self, check: ShellExecutionCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_empty_snapshot_returns_no_findings(
        self, check: ShellExecutionCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0

    async def test_detects_bash_tool(self, check: ShellExecutionCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "bash",
                    "description": "Run a bash command.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_detects_shell_tool(self, check: ShellExecutionCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "shell",
                    "description": "Executes shell commands.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_non_shell_tool_passes(self, check: ShellExecutionCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Returns weather data.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_always_fails_even_with_constraints(
        self, check: ShellExecutionCheck
    ) -> None:
        """Shell execution tools are always flagged, even with schema constraints."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "exec",
                    "description": "Runs a command.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "enum": ["ls", "pwd", "whoami"],
                            },
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Shell tools should always fail regardless of constraints"
