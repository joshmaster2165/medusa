"""PRIV-007: Sudo/Root Elevation.

Detects tools whose names or descriptions reference sudo, su, runas, or
equivalent privilege escalation mechanisms.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SUDO_PATTERN = re.compile(
    r"\b(sudo|su\b|runas|run_as|run-as|setuid|setgid|privilege[d]?_exec|"
    r"escalate|pkexec|doas)\b",
    re.IGNORECASE,
)


class SudoElevationCheck(BaseCheck):
    """Detect tools with sudo/privilege escalation capability."""

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

            match = _SUDO_PATTERN.search(searchable)
            if not match:
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
                        f"Tool '{tool_name}' references privilege escalation "
                        f"mechanism '{match.group(0)}', enabling OS-level bypass."
                    ),
                    evidence=f"Privilege escalation keyword: {match.group(0)}",
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
                    status_extended="No sudo/privilege escalation tools detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
