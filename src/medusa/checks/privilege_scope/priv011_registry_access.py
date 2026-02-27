"""PRIV-011: System Registry Access.

Detects tools that can read or write to Windows Registry or system-level
config paths (/etc/, HKEY_), indicating OS configuration access.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_REGISTRY_PATTERN = re.compile(
    r"\b(regedit|reg(edit|add|delete|query|import|export)|"
    r"HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|"
    r"registry|winreg|read_registry|write_registry|"
    r"/etc/(passwd|shadow|sudoers|hosts|sysctl|crontab))\b",
    re.IGNORECASE,
)


class RegistryAccessCheck(BaseCheck):
    """Detect tools with system registry or global config access."""

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
            schema_str = str(tool.get("inputSchema") or {})
            searchable = f"{tool_name} {description} {schema_str}"

            match = _REGISTRY_PATTERN.search(searchable)
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
                        f"Tool '{tool_name}' has system registry or global config "
                        f"access ('{match.group(0)}'), enabling OS-level tampering."
                    ),
                    evidence=f"Registry/config reference: {match.group(0)}",
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
                    status_extended="No system registry access tools detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
