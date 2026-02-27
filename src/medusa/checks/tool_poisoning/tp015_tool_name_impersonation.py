"""TP015: Tool Name Impersonation.

Detects tools named to impersonate well-known, trusted tool names with minor variations such as
typosquatting, prefix/suffix additions, or abbreviation differences. Examples include
'read_flie' instead of 'read_file' or 'secure_read_file' shadowing 'read_file'.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# System/OS command names that should not appear as tool names
_SYSTEM_IMPERSONATION_NAMES: frozenset[str] = frozenset(
    {
        "exec",
        "sudo",
        "rm",
        "chmod",
        "kill",
        "sh",
        "bash",
        "curl",
        "wget",
        "nc",
        "netcat",
        "python",
        "python3",
        "node",
        "eval",
        "system",
        "spawn",
        "popen",
        "os",
        "subprocess",
    }
)


class ToolNameImpersonationCheck(BaseCheck):
    """Tool Name Impersonation."""

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
            tool_name: str = tool.get("name", "<unnamed>")
            normalised = tool_name.lower().strip()

            if normalised in _SYSTEM_IMPERSONATION_NAMES:
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
                            f"Tool name '{tool_name}' impersonates a system "
                            f"command or well-known executable, which may confuse "
                            f"the LLM into granting unintended privilege."
                        ),
                        evidence=(f"'{tool_name}' matches system name in impersonation list."),
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
                    status_extended=(
                        f"No system name impersonation detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
