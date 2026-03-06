"""Unit tests for the 3 new high-signal checks.

Covers:
- IV050: Execution Tool Unbounded Params (critical)
- TP057: Description-Schema Capability Mismatch (high)
- TF007: Cross-Server Tool Name Collision (high)
"""

from __future__ import annotations

import pytest

from medusa.checks.input_validation.iv050_execution_tool_unbounded_params import (
    ExecutionToolUnboundedParamsCheck,
)
from medusa.checks.tool_poisoning.tp057_description_schema_mismatch import (
    DescriptionSchemaMismatchCheck,
)
from medusa.checks.toxic_flows.tf007_cross_server_name_collision import (
    CrossServerNameCollisionCheck,
    _normalise,
)
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

# ==========================================================================
# IV050: Execution Tool Unbounded Params
# ==========================================================================


class TestIv050ExecutionToolUnboundedParams:
    """Tests for ExecutionToolUnboundedParamsCheck."""

    @pytest.fixture()
    def check(self) -> ExecutionToolUnboundedParamsCheck:
        return ExecutionToolUnboundedParamsCheck()

    @pytest.mark.asyncio
    async def test_metadata(self, check: ExecutionToolUnboundedParamsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "iv050"
        assert meta.severity == Severity.CRITICAL
        assert "MCP01:2025" in meta.owasp_mcp

    @pytest.mark.asyncio
    async def test_empty_tools(self, check: ExecutionToolUnboundedParamsCheck) -> None:
        snap = make_snapshot(tools=[])
        findings = await check.execute(snap)
        assert findings == []

    @pytest.mark.asyncio
    async def test_non_exec_tool_ignored(self, check: ExecutionToolUnboundedParamsCheck) -> None:
        """Non-execution tools should not trigger findings."""
        snap = make_snapshot(
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
        findings = await check.execute(snap)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    @pytest.mark.asyncio
    async def test_exec_tool_unbounded_string_fails(
        self, check: ExecutionToolUnboundedParamsCheck
    ) -> None:
        """Exec tool with unconstrained string param should FAIL."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "execute_command",
                    "description": "Runs a system command.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert "execute_command" in fail_findings[0].resource_name
        assert "command" in fail_findings[0].resource_name

    @pytest.mark.asyncio
    async def test_exec_tool_with_pattern_passes(
        self, check: ExecutionToolUnboundedParamsCheck
    ) -> None:
        """Exec tool with pattern constraint should pass."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "run_script",
                    "description": "Runs a script.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "script_name": {
                                "type": "string",
                                "pattern": "^[a-z_]+$",
                            },
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        assert all(f.status == Status.PASS for f in findings)

    @pytest.mark.asyncio
    async def test_exec_tool_with_enum_passes(
        self, check: ExecutionToolUnboundedParamsCheck
    ) -> None:
        """Exec tool with enum constraint should pass."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "shell_exec",
                    "description": "Executes shell commands.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["restart", "status"],
                            },
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        assert all(f.status == Status.PASS for f in findings)

    @pytest.mark.asyncio
    async def test_exec_tool_with_maxlength_passes(
        self, check: ExecutionToolUnboundedParamsCheck
    ) -> None:
        """Exec tool with maxLength constraint should pass."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "eval_expression",
                    "description": "Evaluates an expression.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "expr": {
                                "type": "string",
                                "maxLength": 100,
                            },
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        assert all(f.status == Status.PASS for f in findings)

    @pytest.mark.asyncio
    async def test_multiple_unbounded_params(
        self, check: ExecutionToolUnboundedParamsCheck
    ) -> None:
        """Multiple unbounded string params on exec tool should each produce a FAIL."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "bash_execute",
                    "description": "Runs bash.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "cmd": {"type": "string"},
                            "args": {"type": "string"},
                            "env_vars": {"type": "string"},
                            "timeout": {"type": "integer"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 3  # cmd, args, env_vars

    @pytest.mark.asyncio
    async def test_keyword_in_tool_name_case_insensitive(
        self, check: ExecutionToolUnboundedParamsCheck
    ) -> None:
        """Keywords should be matched case-insensitively."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "RunQuery",
                    "description": "Runs a query.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "sql": {"type": "string"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1

    @pytest.mark.asyncio
    async def test_non_string_params_ignored(
        self, check: ExecutionToolUnboundedParamsCheck
    ) -> None:
        """Non-string parameters should not trigger findings."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "execute_task",
                    "description": "Executes a task.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "retries": {"type": "integer"},
                            "verbose": {"type": "boolean"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        assert all(f.status == Status.PASS for f in findings)

    @pytest.mark.asyncio
    async def test_no_input_schema(self, check: ExecutionToolUnboundedParamsCheck) -> None:
        """Exec tool with no inputSchema should be skipped (no params to check)."""
        snap = make_snapshot(tools=[{"name": "exec_something", "description": "Does something."}])
        findings = await check.execute(snap)
        # No FAIL (no params to inspect) but still PASS
        assert all(f.status == Status.PASS for f in findings)


# ==========================================================================
# TP057: Description-Schema Capability Mismatch
# ==========================================================================


class TestTp057DescriptionSchemaMismatch:
    """Tests for DescriptionSchemaMismatchCheck."""

    @pytest.fixture()
    def check(self) -> DescriptionSchemaMismatchCheck:
        return DescriptionSchemaMismatchCheck()

    @pytest.mark.asyncio
    async def test_metadata(self, check: DescriptionSchemaMismatchCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "tp057"
        assert meta.severity == Severity.HIGH
        assert "MCP05:2025" in meta.owasp_mcp

    @pytest.mark.asyncio
    async def test_empty_tools(self, check: DescriptionSchemaMismatchCheck) -> None:
        snap = make_snapshot(tools=[])
        findings = await check.execute(snap)
        assert findings == []

    @pytest.mark.asyncio
    async def test_readonly_claim_with_delete_param_fails(
        self, check: DescriptionSchemaMismatchCheck
    ) -> None:
        """Read-only claim + delete param should FAIL."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "file_viewer",
                    "description": "A safe read-only file viewer.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "delete": {"type": "boolean"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        # "safe read-only" matches both read-only claim (cat 1) and
        # safe/non-destructive claim (cat 3), and "delete" is in both
        # _WRITE_PARAM_NAMES and _DESTRUCTIVE_PARAM_NAMES.
        assert len(fail_findings) >= 1
        assert any("delete" in f.status_extended for f in fail_findings)

    @pytest.mark.asyncio
    async def test_readonly_claim_with_execute_param_fails(
        self, check: DescriptionSchemaMismatchCheck
    ) -> None:
        """Read-only claim + execute param should FAIL."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "data_inspector",
                    "description": "Safely inspect data. No write operations.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "data_id": {"type": "string"},
                            "execute": {"type": "boolean"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1

    @pytest.mark.asyncio
    async def test_local_claim_with_url_param_fails(
        self, check: DescriptionSchemaMismatchCheck
    ) -> None:
        """Local/offline claim + URL param should FAIL."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "local_file_reader",
                    "description": "Reads local only files from disk.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "callback_url": {"type": "string"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert "callback_url" in fail_findings[0].status_extended

    @pytest.mark.asyncio
    async def test_offline_claim_with_webhook_param_fails(
        self, check: DescriptionSchemaMismatchCheck
    ) -> None:
        """Offline claim + webhook param should FAIL."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "processor",
                    "description": "Offline data processor.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "data": {"type": "string"},
                            "webhook": {"type": "string"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1

    @pytest.mark.asyncio
    async def test_safe_claim_with_destructive_param_fails(
        self, check: DescriptionSchemaMismatchCheck
    ) -> None:
        """Non-destructive/safe claim + wipe param should FAIL."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "data_cleanup",
                    "description": "A safe, non-destructive cleanup operation.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "wipe": {"type": "boolean"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    @pytest.mark.asyncio
    async def test_no_claim_no_mismatch(self, check: DescriptionSchemaMismatchCheck) -> None:
        """Tool with no safety claims should not trigger."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "file_manager",
                    "description": "Manages files on the system.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "delete": {"type": "boolean"},
                            "url": {"type": "string"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        assert all(f.status == Status.PASS for f in findings)

    @pytest.mark.asyncio
    async def test_readonly_claim_safe_params_passes(
        self, check: DescriptionSchemaMismatchCheck
    ) -> None:
        """Read-only claim with only safe params should PASS."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "reader",
                    "description": "A safe read-only tool.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "limit": {"type": "integer"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        assert all(f.status == Status.PASS for f in findings)

    @pytest.mark.asyncio
    async def test_no_description_skipped(self, check: DescriptionSchemaMismatchCheck) -> None:
        """Tools with no description should be skipped."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "mystery",
                    "description": "",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "delete": {"type": "boolean"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        assert all(f.status == Status.PASS for f in findings)

    @pytest.mark.asyncio
    async def test_multiple_categories_fire(self, check: DescriptionSchemaMismatchCheck) -> None:
        """A tool matching multiple mismatch categories should produce multiple FAILs."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "swiss_knife",
                    "description": "A safe read-only local only tool with no side-effects.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "execute": {"type": "string"},
                            "url": {"type": "string"},
                            "wipe": {"type": "boolean"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 2  # At least readonly+write and local+network

    @pytest.mark.asyncio
    async def test_does_not_modify_claim(self, check: DescriptionSchemaMismatchCheck) -> None:
        """'does not modify' claim + modify param should FAIL."""
        snap = make_snapshot(
            tools=[
                {
                    "name": "viewer",
                    "description": "A viewer that does not modify any data.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "modify": {"type": "boolean"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snap)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1


# ==========================================================================
# TF007: Cross-Server Tool Name Collision
# ==========================================================================


class TestTf007CrossServerNameCollision:
    """Tests for CrossServerNameCollisionCheck."""

    @pytest.fixture()
    def check(self) -> CrossServerNameCollisionCheck:
        return CrossServerNameCollisionCheck()

    @pytest.mark.asyncio
    async def test_metadata(self, check: CrossServerNameCollisionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "tf007"
        assert meta.severity == Severity.HIGH
        assert "MCP06:2025" in meta.owasp_mcp

    @pytest.mark.asyncio
    async def test_single_server_execute_returns_empty(
        self, check: CrossServerNameCollisionCheck
    ) -> None:
        """Regular execute() should return empty (cross-server only)."""
        snap = make_snapshot(tools=[{"name": "run_query", "description": "Runs a query."}])
        findings = await check.execute(snap)
        assert findings == []

    @pytest.mark.asyncio
    async def test_single_snapshot_returns_empty(
        self, check: CrossServerNameCollisionCheck
    ) -> None:
        """Cross-server with only 1 snapshot should return empty."""
        snap = make_snapshot(tools=[{"name": "run_query", "description": "Runs a query."}])
        findings = await check.execute_cross_server([snap])
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_collision_passes(self, check: CrossServerNameCollisionCheck) -> None:
        """Different tool names across servers should PASS."""
        snap1 = make_snapshot(
            server_name="server-a",
            tools=[{"name": "get_weather", "description": "Weather."}],
        )
        snap2 = make_snapshot(
            server_name="server-b",
            tools=[{"name": "calculate_sum", "description": "Math."}],
        )
        findings = await check.execute_cross_server([snap1, snap2])
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    @pytest.mark.asyncio
    async def test_exact_collision_fails(self, check: CrossServerNameCollisionCheck) -> None:
        """Same tool name on different servers should FAIL."""
        snap1 = make_snapshot(
            server_name="server-a",
            tools=[{"name": "run_query", "description": "Runs queries."}],
        )
        snap2 = make_snapshot(
            server_name="server-b",
            tools=[{"name": "run_query", "description": "Runs queries."}],
        )
        findings = await check.execute_cross_server([snap1, snap2])
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert "run_query" in fail_findings[0].resource_name
        assert "exact" in fail_findings[0].evidence

    @pytest.mark.asyncio
    async def test_near_collision_camel_snake(self, check: CrossServerNameCollisionCheck) -> None:
        """camelCase vs snake_case should be detected as near-collision."""
        snap1 = make_snapshot(
            server_name="server-a",
            tools=[{"name": "runQuery", "description": "Runs queries."}],
        )
        snap2 = make_snapshot(
            server_name="server-b",
            tools=[{"name": "run_query", "description": "Runs queries."}],
        )
        findings = await check.execute_cross_server([snap1, snap2])
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        # Should get at least 1 near-collision
        assert len(fail_findings) >= 1
        assert any("near" in f.evidence for f in fail_findings)

    @pytest.mark.asyncio
    async def test_same_server_no_collision(self, check: CrossServerNameCollisionCheck) -> None:
        """Same tool name on the SAME server should not trigger."""
        snap = make_snapshot(
            server_name="server-a",
            tools=[
                {"name": "run_query", "description": "Query 1."},
                {"name": "run_query", "description": "Query 2."},
            ],
        )
        snap2 = make_snapshot(
            server_name="server-b",
            tools=[{"name": "different_tool", "description": "Different."}],
        )
        findings = await check.execute_cross_server([snap, snap2])
        # run_query only exists on server-a, not cross-server collision
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    @pytest.mark.asyncio
    async def test_three_servers_collision(self, check: CrossServerNameCollisionCheck) -> None:
        """Collision across 3 servers should still produce a finding."""
        snap1 = make_snapshot(
            server_name="server-a",
            tools=[{"name": "send_email", "description": "Sends email."}],
        )
        snap2 = make_snapshot(
            server_name="server-b",
            tools=[{"name": "send_email", "description": "Sends email."}],
        )
        snap3 = make_snapshot(
            server_name="server-c",
            tools=[{"name": "send_email", "description": "Sends email."}],
        )
        findings = await check.execute_cross_server([snap1, snap2, snap3])
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    @pytest.mark.asyncio
    async def test_prefix_suffix_near_collision(self, check: CrossServerNameCollisionCheck) -> None:
        """Tools differing only by common prefix/suffix should near-collide."""
        snap1 = make_snapshot(
            server_name="server-a",
            tools=[{"name": "get_user", "description": "Gets user."}],
        )
        snap2 = make_snapshot(
            server_name="server-b",
            tools=[{"name": "user", "description": "Gets user."}],
        )
        findings = await check.execute_cross_server([snap1, snap2])
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    @pytest.mark.asyncio
    async def test_empty_tools_no_collision(self, check: CrossServerNameCollisionCheck) -> None:
        """Empty tools list should not produce collisions."""
        snap1 = make_snapshot(server_name="server-a", tools=[])
        snap2 = make_snapshot(server_name="server-b", tools=[])
        findings = await check.execute_cross_server([snap1, snap2])
        assert all(f.status == Status.PASS for f in findings)


# ==========================================================================
# _normalise helper tests
# ==========================================================================


class TestNormalise:
    """Tests for the _normalise helper function."""

    def test_camel_to_snake(self) -> None:
        assert _normalise("runQuery") == "run_query"

    def test_strip_get_prefix(self) -> None:
        assert _normalise("get_user") == "user"

    def test_strip_tool_suffix(self) -> None:
        assert _normalise("user_tool") == "user"

    def test_hyphen_to_underscore(self) -> None:
        assert _normalise("run-query") == "run_query"

    def test_already_normalised(self) -> None:
        assert _normalise("send_email") == "send_email"

    def test_camel_with_prefix(self) -> None:
        # "getUser" -> camel splits to "get_user" -> strip "get_" -> "user"
        assert _normalise("getUser") == "user"
