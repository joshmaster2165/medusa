"""PRIV-009: Unrestricted Process Spawning.

Detects tools with names or descriptions suggesting process spawning capability
(exec, fork, spawn, popen, subprocess) without allowlist constraints.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_PROCESS_SPAWN_PATTERN = re.compile(
    r"\b(spawn|fork|popen|subprocess|proc_open|createprocess|"
    r"process_create|start_process|launch_process|exec_process)\b",
    re.IGNORECASE,
)


class ProcessSpawningCheck(BaseCheck):
    """Detect tools with arbitrary process spawning capability."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            description = tool.get("description", "") or ""
            searchable = f"{tool_name} {description}"

            match = _PROCESS_SPAWN_PATTERN.search(searchable)
            if not match:
                continue

            # Check if command param has enum constraint
            input_schema = tool.get("inputSchema") or {}
            properties = (
                input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
            )
            is_constrained = any(
                isinstance(v, dict) and bool(v.get("enum")) for v in properties.values()
            )
            if is_constrained:
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
                        f"Tool '{tool_name}' has process spawning capability "
                        f"('{match.group(0)}') without allowlist constraints, "
                        f"effectively providing remote shell access."
                    ),
                    evidence=f"Process spawn keyword: {match.group(0)}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        if not findings and snapshot.tools:
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
                    status_extended="No unrestricted process spawning tools detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
