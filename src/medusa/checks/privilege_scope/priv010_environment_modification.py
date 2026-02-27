"""PRIV-010: Environment Variable Modification.

Detects tools that can set, modify, or delete environment variables, enabling
PATH hijacking, LD_PRELOAD attacks, and configuration tampering.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_ENV_MOD_PATTERN = re.compile(
    r"\b(set_env\w*|setenv|putenv|set_environment\w*|env_set|"
    r"modify_env|update_env|export_env|unset_env|"
    r"set.*environ|environ.*set)\b",
    re.IGNORECASE,
)
_ENV_PARAM_NAMES = {
    "env_var",
    "env_name",
    "env_key",
    "variable",
    "env_value",
    "environment_variable",
}


class EnvironmentModificationCheck(BaseCheck):
    """Detect tools that can modify environment variables."""

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
            input_schema = tool.get("inputSchema") or {}
            properties = (
                input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
            )
            searchable = f"{tool_name} {description}"

            name_match = _ENV_MOD_PATTERN.search(searchable)
            has_env_param = any(p.lower() in _ENV_PARAM_NAMES for p in properties)

            if not (name_match or has_env_param):
                continue

            evidence = (
                name_match.group(0) if name_match else f"env params: {list(properties.keys())}"
            )
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
                        f"Tool '{tool_name}' can modify environment variables "
                        f"({evidence}), enabling PATH hijacking or config tampering."
                    ),
                    evidence=evidence,
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
                    status_extended="No environment modification tools detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
