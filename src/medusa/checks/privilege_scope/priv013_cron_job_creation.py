"""PRIV-013: Cron/Scheduled Task Creation.

Detects tools that can create cron jobs, scheduled tasks, or systemd timers —
a common persistence mechanism used by attackers.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_CRON_PATTERN = re.compile(
    r"\b(cron(tab)?|create.*cron|schedule.*task|scheduled.task|"
    r"at\.exe|schtasks|systemd.*timer|timer.*systemd|"
    r"add.*cron|install.*cron|/etc/cron\.d|/var/spool/cron)\b",
    re.IGNORECASE,
)


class CronJobCreationCheck(BaseCheck):
    """Detect tools with scheduled task/cron job creation capability."""

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

            match = _CRON_PATTERN.search(searchable)
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
                        f"Tool '{tool_name}' can create scheduled tasks/cron jobs "
                        f"('{match.group(0)}'), enabling persistence attacks."
                    ),
                    evidence=f"Scheduled task keyword: {match.group(0)}",
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
                    status_extended="No cron/scheduled task creation tools detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
