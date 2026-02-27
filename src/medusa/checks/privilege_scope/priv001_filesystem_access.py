"""PRIV-001: Detect overprivileged filesystem-access tools.

Identifies tools whose names match known filesystem operation patterns and
checks whether their schemas or server configuration restrict which directories
and files can be accessed. Unrestricted filesystem tools violate the principle
of least privilege.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import FS_TOOL_PATTERNS, PATH_PARAM_NAMES


def _is_filesystem_tool(tool_name: str) -> bool:
    """Return *True* if the tool name matches any filesystem pattern."""
    for pattern in FS_TOOL_PATTERNS:
        if pattern.search(tool_name):
            return True
    return False


def _has_path_restriction(tool: dict) -> tuple[bool, str]:
    """Check if a filesystem tool restricts accessible paths.

    Returns a tuple of (is_restricted, explanation).
    """
    input_schema = tool.get("inputSchema")
    if not input_schema or not isinstance(input_schema, dict):
        return False, "No inputSchema defined"

    properties = input_schema.get("properties", {})
    if not isinstance(properties, dict):
        return False, "inputSchema has no valid properties"

    restrictions_found: list[str] = []

    for param_name, param_def in properties.items():
        if not isinstance(param_def, dict):
            continue

        normalised = param_name.lower().strip()
        if normalised not in PATH_PARAM_NAMES:
            continue

        # Check for schema-level path constraints
        has_pattern = bool(param_def.get("pattern"))
        has_enum = bool(param_def.get("enum"))

        if has_pattern:
            restrictions_found.append(
                f"'{param_name}' has pattern constraint: {param_def['pattern']}"
            )
        if has_enum:
            restrictions_found.append(f"'{param_name}' is restricted to enum values")

    if restrictions_found:
        return True, "; ".join(restrictions_found)

    return False, "No path-restricting constraints found on path parameters"


class FilesystemAccessCheck(BaseCheck):
    """Check for overprivileged filesystem tools."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        fs_tools_found = 0

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")

            if not _is_filesystem_tool(tool_name):
                continue

            fs_tools_found += 1

            is_restricted, explanation = _has_path_restriction(tool)

            if not is_restricted:
                # Also check server args/config for directory restrictions
                config_restriction = _check_server_config_restrictions(snapshot, tool_name)

                if config_restriction:
                    # Server-level config provides some restriction
                    continue

                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=(
                            f"Filesystem tool '{tool_name}' provides "
                            f"unrestricted file access. {explanation}. "
                            f"This tool can potentially read or modify any "
                            f"file accessible to the server process."
                        ),
                        evidence=explanation,
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and fs_tools_found > 0:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"All {fs_tools_found} filesystem tool(s) have "
                        f"appropriate path restrictions."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings


def _check_server_config_restrictions(snapshot: ServerSnapshot, tool_name: str) -> bool:
    """Heuristic: check server args and config for directory-restriction hints.

    Looks for common CLI patterns like ``--allowed-dir``, ``--root``,
    ``--sandbox``, or config keys that suggest path scoping.
    """
    restriction_hints = {
        "allowed",
        "allowlist",
        "root",
        "sandbox",
        "chroot",
        "base-dir",
        "base_dir",
        "basedir",
        "workdir",
        "workspace",
        "restrict",
        "scope",
    }

    # Check server command-line arguments
    for arg in snapshot.args:
        arg_lower = arg.lower()
        for hint in restriction_hints:
            if hint in arg_lower:
                return True

    # Check raw config for restriction keys
    if snapshot.config_raw and isinstance(snapshot.config_raw, dict):
        config_str = str(snapshot.config_raw).lower()
        for hint in restriction_hints:
            if hint in config_str:
                return True

    return False
