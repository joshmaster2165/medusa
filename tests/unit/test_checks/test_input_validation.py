"""Unit tests for all Input Validation checks (IV-001 through IV-005).

Each check is tested for:
- FAIL on the vulnerable_snapshot
- PASS on the secure_snapshot
- Graceful handling of the empty_snapshot (no tools)
- Additional edge cases (missing schemas, constrained params, boundary cases)
"""

from __future__ import annotations

import pytest

from medusa.checks.input_validation.iv001_command_injection import CommandInjectionCheck
from medusa.checks.input_validation.iv002_path_traversal import PathTraversalCheck
from medusa.checks.input_validation.iv003_sql_injection import SqlInjectionCheck
from medusa.checks.input_validation.iv004_missing_schema import MissingSchemaCheck
from medusa.checks.input_validation.iv005_permissive_schema import PermissiveSchemaCheck
from medusa.core.check import ServerSnapshot
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

# ==========================================================================
# IV-001: Command Injection Risk
# ==========================================================================


class TestIV001CommandInjection:
    """Tests for CommandInjectionCheck."""

    @pytest.fixture()
    def check(self) -> CommandInjectionCheck:
        return CommandInjectionCheck()

    async def test_metadata_loads_correctly(self, check: CommandInjectionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "iv001", "Check ID should be iv001"
        assert meta.category == "input_validation", "Category should be input_validation"
        assert meta.severity == Severity.CRITICAL, "Severity should be CRITICAL"

    async def test_fails_on_unconstrained_command_param(
        self, check: CommandInjectionCheck, vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "Should flag 'execute_command' tool with unconstrained 'command' param"
        )
        exec_findings = [
            f for f in fail_findings if "execute_command" in f.resource_name
        ]
        assert len(exec_findings) >= 1, (
            "execute_command.command should be flagged for command injection risk"
        )

    async def test_passes_on_secure_snapshot(
        self, check: CommandInjectionCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 1, "Should produce exactly one PASS finding"
        assert findings[0].status == Status.PASS, "Finding should be PASS"

    async def test_empty_snapshot_returns_no_findings(
        self, check: CommandInjectionCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0, "Empty snapshot should produce zero findings"

    async def test_constrained_command_param_passes(
        self, check: CommandInjectionCheck
    ) -> None:
        """A 'command' param with an enum constraint should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "safe_executor",
                    "description": "Runs allowed commands only.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "enum": ["ls", "pwd", "whoami"],
                            },
                        },
                        "required": ["command"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, (
            "Enum-constrained command param should PASS"
        )

    async def test_pattern_constrained_command_passes(
        self, check: CommandInjectionCheck
    ) -> None:
        """A 'command' param with a pattern constraint should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "regex_executor",
                    "description": "Runs commands matching a pattern.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "pattern": "^[a-zA-Z_]+$",
                            },
                        },
                        "required": ["command"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, (
            "Pattern-constrained command param should PASS"
        )

    async def test_non_string_command_param_is_skipped(
        self, check: CommandInjectionCheck
    ) -> None:
        """A 'command' param with type integer should be ignored."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "int_cmd",
                    "description": "Takes a command code.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "integer"},
                        },
                        "required": ["command"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce one finding"
        assert findings[0].status == Status.PASS, (
            "Integer 'command' param should not be flagged"
        )

    async def test_multiple_shell_params_flagged(self, check: CommandInjectionCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "multi_shell",
                    "description": "Runs multiple things.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "cmd": {"type": "string"},
                            "shell": {"type": "string"},
                            "script": {"type": "string"},
                        },
                        "required": ["cmd"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 3, (
            "All three unconstrained shell params should be flagged"
        )

    async def test_tool_with_no_input_schema(self, check: CommandInjectionCheck) -> None:
        """Tools without inputSchema are handled by IV-004, not IV-001."""
        snapshot = make_snapshot(
            tools=[{"name": "no_schema", "description": "No schema tool."}]
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1, (
            "Tool with no schema should result in PASS for IV-001"
        )

    async def test_non_shell_param_names_pass(self, check: CommandInjectionCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "normal_tool",
                    "description": "Normal tool.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "message": {"type": "string"},
                        },
                        "required": ["name"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, (
            "Non-shell-related param names should PASS"
        )


# ==========================================================================
# IV-002: Path Traversal Risk
# ==========================================================================


class TestIV002PathTraversal:
    """Tests for PathTraversalCheck."""

    @pytest.fixture()
    def check(self) -> PathTraversalCheck:
        return PathTraversalCheck()

    async def test_metadata_loads_correctly(self, check: PathTraversalCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "iv002", "Check ID should be iv002"
        assert meta.category == "input_validation", "Category should be input_validation"
        assert meta.severity == Severity.HIGH, "Severity should be HIGH"

    async def test_fails_on_unconstrained_path_param(
        self, check: PathTraversalCheck, vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "Should flag 'file_reader' tool with unconstrained 'path' param"
        )
        path_findings = [
            f for f in fail_findings if "file_reader" in f.resource_name
        ]
        assert len(path_findings) >= 1, (
            "file_reader.path should be flagged for path traversal risk"
        )

    async def test_passes_on_secure_snapshot(
        self, check: PathTraversalCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1, "Secure snapshot should PASS"

    async def test_empty_snapshot_returns_no_findings(
        self, check: PathTraversalCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0, "Empty snapshot should produce zero findings"

    async def test_pattern_without_slash_blocks_traversal(
        self, check: PathTraversalCheck
    ) -> None:
        """A restrictive pattern that does not allow '/' or '.' blocks traversal."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "safe_reader",
                    "description": "Reads files safely.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "pattern": "^[a-zA-Z0-9_]+$",
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
        assert len(pass_findings) >= 1, (
            "Path param with restrictive pattern (no / or .) should PASS"
        )

    async def test_pattern_with_explicit_dotdot_block_passes(
        self, check: PathTraversalCheck
    ) -> None:
        """A pattern that explicitly contains '..' rejection should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "dotdot_blocker",
                    "description": "Blocks .. in paths.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "pattern": r"^(?!.*\.\.)[a-zA-Z0-9_/]+$",
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
        assert len(pass_findings) >= 1, (
            "Pattern with explicit '..' rejection should PASS"
        )

    async def test_enum_constrained_path_passes(self, check: PathTraversalCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "limited_reader",
                    "description": "Reads from allowed paths only.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "enum": ["/data/report.csv", "/data/log.txt"],
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
        assert len(pass_findings) >= 1, (
            "Enum-constrained path param should PASS"
        )

    async def test_various_path_param_names(self, check: PathTraversalCheck) -> None:
        """Multiple path-like param names should all be checked."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "multi_path_tool",
                    "description": "Uses many path params.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string"},
                            "directory": {"type": "string"},
                            "filepath": {"type": "string"},
                        },
                        "required": ["file"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 3, (
            "All three unconstrained path-like params should be flagged"
        )

    async def test_non_path_params_pass(self, check: PathTraversalCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "safe_tool",
                    "description": "No path params.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "count": {"type": "integer"},
                        },
                        "required": ["name"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Non-path params should PASS"


# ==========================================================================
# IV-003: SQL Injection Risk
# ==========================================================================


class TestIV003SqlInjection:
    """Tests for SqlInjectionCheck."""

    @pytest.fixture()
    def check(self) -> SqlInjectionCheck:
        return SqlInjectionCheck()

    async def test_metadata_loads_correctly(self, check: SqlInjectionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "iv003", "Check ID should be iv003"
        assert meta.category == "input_validation", "Category should be input_validation"
        assert meta.severity == Severity.HIGH, "Severity should be HIGH"

    async def test_fails_on_unconstrained_query_param(
        self, check: SqlInjectionCheck, vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "Should flag 'db_query' tool with unconstrained 'query' param"
        )
        query_findings = [
            f for f in fail_findings if "db_query" in f.resource_name
        ]
        assert len(query_findings) >= 1, (
            "db_query.query should be flagged for SQL injection risk"
        )

    async def test_passes_on_secure_snapshot(
        self, check: SqlInjectionCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 1, "Should produce exactly one PASS finding"
        assert findings[0].status == Status.PASS, "Finding should be PASS"

    async def test_empty_snapshot_returns_no_findings(
        self, check: SqlInjectionCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0, "Empty snapshot should produce zero findings"

    async def test_enum_constrained_query_passes(self, check: SqlInjectionCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "safe_db",
                    "description": "Runs predefined queries.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "enum": ["SELECT * FROM users", "SELECT count(*) FROM orders"],
                            },
                        },
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce one finding"
        assert findings[0].status == Status.PASS, (
            "Enum-constrained query param should PASS"
        )

    async def test_pattern_constrained_query_passes(
        self, check: SqlInjectionCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "regex_db",
                    "description": "Runs pattern-constrained queries.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "pattern": "^SELECT [a-z_]+ FROM [a-z_]+$",
                            },
                        },
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce one finding"
        assert findings[0].status == Status.PASS, (
            "Pattern-constrained query param should PASS"
        )

    async def test_multiple_sql_params_flagged(self, check: SqlInjectionCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "complex_db",
                    "description": "Complex database tool.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "sql": {"type": "string"},
                            "where": {"type": "string"},
                            "filter": {"type": "string"},
                        },
                        "required": ["sql"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 3, (
            "All three unconstrained SQL-like params should be flagged"
        )

    async def test_maxlength_still_fails_but_notes_it(
        self, check: SqlInjectionCheck
    ) -> None:
        """A query param with maxLength but no pattern/enum should still FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "limited_db",
                    "description": "DB with length limit.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "maxLength": 64,
                            },
                        },
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "maxLength alone should not prevent a FAIL"
        )
        assert "maxLength" in fail_findings[0].status_extended, (
            "The finding should mention the partial maxLength control"
        )

    async def test_non_string_sql_param_skipped(self, check: SqlInjectionCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "int_query",
                    "description": "Takes query as int.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "integer"},
                        },
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce one finding"
        assert findings[0].status == Status.PASS, (
            "Non-string 'query' param should not be flagged"
        )


# ==========================================================================
# IV-004: Missing or Empty Input Schema
# ==========================================================================


class TestIV004MissingSchema:
    """Tests for MissingSchemaCheck."""

    @pytest.fixture()
    def check(self) -> MissingSchemaCheck:
        return MissingSchemaCheck()

    async def test_metadata_loads_correctly(self, check: MissingSchemaCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "iv004", "Check ID should be iv004"
        assert meta.category == "input_validation", "Category should be input_validation"
        assert meta.severity == Severity.HIGH, "Severity should be HIGH"

    async def test_fails_on_missing_schema(
        self, check: MissingSchemaCheck, vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "Should flag 'mystery_tool' which has no inputSchema"
        )
        mystery_findings = [
            f for f in fail_findings if f.resource_name == "mystery_tool"
        ]
        assert len(mystery_findings) >= 1, (
            "mystery_tool should be flagged for missing schema"
        )

    async def test_passes_on_secure_snapshot(
        self, check: MissingSchemaCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1, "Secure snapshot should PASS"

    async def test_empty_snapshot_returns_no_findings(
        self, check: MissingSchemaCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0, "Empty snapshot should produce zero findings"

    async def test_tool_with_none_input_schema(self, check: MissingSchemaCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "null_schema",
                    "description": "Has null schema.",
                    "inputSchema": None,
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "None inputSchema should be flagged"
        )

    async def test_tool_with_no_properties_key(self, check: MissingSchemaCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "no_props",
                    "description": "Schema without properties.",
                    "inputSchema": {"type": "object"},
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "Schema without 'properties' should be flagged"
        )

    async def test_tool_with_no_type_field(self, check: MissingSchemaCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "no_type",
                    "description": "Schema without type.",
                    "inputSchema": {
                        "properties": {"x": {"type": "string"}},
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "Schema without 'type' field should be flagged"
        )

    async def test_complete_schema_passes(self, check: MissingSchemaCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "complete_tool",
                    "description": "Has a proper schema.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                        },
                        "required": ["name"],
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce one finding"
        assert findings[0].status == Status.PASS, "Complete schema should PASS"

    async def test_empty_properties_with_type_passes(
        self, check: MissingSchemaCheck
    ) -> None:
        """A zero-arg tool with type:object and empty properties is intentional."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "zero_arg",
                    "description": "Takes no arguments.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1, (
            "Zero-arg tool with type and empty properties should PASS"
        )

    async def test_non_dict_input_schema_fails(self, check: MissingSchemaCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "string_schema",
                    "description": "Schema is a string.",
                    "inputSchema": "not a dict",
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "Non-dict inputSchema should be flagged"
        )
        assert "not an object" in fail_findings[0].evidence, (
            "Evidence should mention the schema is not an object"
        )


# ==========================================================================
# IV-005: Overly Permissive Tool Input Schema
# ==========================================================================


class TestIV005PermissiveSchema:
    """Tests for PermissiveSchemaCheck."""

    @pytest.fixture()
    def check(self) -> PermissiveSchemaCheck:
        return PermissiveSchemaCheck()

    async def test_metadata_loads_correctly(self, check: PermissiveSchemaCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "iv005", "Check ID should be iv005"
        assert meta.category == "input_validation", "Category should be input_validation"
        assert meta.severity == Severity.MEDIUM, "Severity should be MEDIUM"

    async def test_fails_on_permissive_schema(
        self, check: PermissiveSchemaCheck, vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "Should flag 'loose_tool' with additionalProperties:true and no required"
        )
        loose_findings = [
            f for f in fail_findings if f.resource_name == "loose_tool"
        ]
        assert len(loose_findings) >= 1, (
            "loose_tool should be flagged for permissive schema"
        )

    async def test_passes_on_secure_snapshot(
        self, check: PermissiveSchemaCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1, "Secure snapshot should PASS"

    async def test_empty_snapshot_returns_no_findings(
        self, check: PermissiveSchemaCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0, "Empty snapshot should produce zero findings"

    async def test_additional_properties_true_fails(
        self, check: PermissiveSchemaCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "extra_props_tool",
                    "description": "Allows extra properties.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                        },
                        "required": ["name"],
                        "additionalProperties": True,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "additionalProperties: true should be flagged"
        )
        assert "additionalProperties" in fail_findings[0].status_extended, (
            "Finding should mention additionalProperties"
        )

    async def test_missing_additional_properties_fails(
        self, check: PermissiveSchemaCheck
    ) -> None:
        """When additionalProperties is omitted, JSON Schema defaults to true."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "default_props_tool",
                    "description": "No additionalProperties set.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "data": {"type": "string"},
                        },
                        "required": ["data"],
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "Missing additionalProperties (defaults to true) should be flagged"
        )

    async def test_no_required_array_fails(self, check: PermissiveSchemaCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "no_required_tool",
                    "description": "No required array.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "action": {"type": "string"},
                        },
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "Missing 'required' array should be flagged"
        )
        assert "required" in fail_findings[0].status_extended.lower(), (
            "Finding should mention missing required"
        )

    async def test_empty_required_array_fails(self, check: PermissiveSchemaCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "empty_required_tool",
                    "description": "Empty required array.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "x": {"type": "string"},
                        },
                        "required": [],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "Empty 'required' array should be flagged"
        )

    async def test_well_defined_schema_passes(self, check: PermissiveSchemaCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "strict_tool",
                    "description": "Properly defined schema.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "age": {"type": "integer"},
                        },
                        "required": ["name", "age"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, (
            "Well-defined schema should PASS"
        )

    async def test_tool_with_no_schema_skipped(self, check: PermissiveSchemaCheck) -> None:
        """Tools with missing schemas are handled by IV-004, not IV-005."""
        snapshot = make_snapshot(
            tools=[{"name": "no_schema_tool", "description": "No schema."}]
        )
        findings = await check.execute(snapshot)
        # Should produce a PASS because no schemas to evaluate as permissive
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1, (
            "Tool without schema should result in PASS for IV-005"
        )

    async def test_tool_with_empty_properties_skipped(
        self, check: PermissiveSchemaCheck
    ) -> None:
        """Empty properties are handled by IV-004, IV-005 skips them."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "empty_props",
                    "description": "Empty properties.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1, (
            "Tool with empty properties should be skipped by IV-005 and result in PASS"
        )

    async def test_both_issues_in_one_finding(self, check: PermissiveSchemaCheck) -> None:
        """additionalProperties:true AND no required should both appear in one finding."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "double_issue",
                    "description": "Both issues present.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "x": {"type": "string"},
                        },
                        "additionalProperties": True,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, (
            "Should produce exactly one FAIL finding with both issues"
        )
        status_text = fail_findings[0].status_extended.lower()
        assert "additionalproperties" in status_text, (
            "Should mention additionalProperties issue"
        )
        assert "required" in status_text, (
            "Should mention missing required issue"
        )
