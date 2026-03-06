"""AGENT-029: Tool Without Bounded Duration/Timeout.

Detects resource-intensive tools that lack timeout or duration limit
parameters, which could allow unbounded execution.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.schema import TIMEOUT_PARAM_NAMES

_RESOURCE_INTENSIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(query|execute|search|scan|fetch|process)\b", re.IGNORECASE),
    re.compile(r"\b(run|compute|generate|analyze|crawl|scrape)\b", re.IGNORECASE),
    re.compile(r"\b(download|upload|sync|migrate|export|import)\b", re.IGNORECASE),
    re.compile(r"\b(batch|bulk|aggregate|transform|compile)\b", re.IGNORECASE),
]


class UnboundedDurationCheck(BaseCheck):
    """Detect resource-intensive tools without timeout parameters."""

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
            description = tool.get("description", "")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {})
            param_names_lower = {p.lower() for p in properties}

            combined = f"{tool_name} {description}"
            is_intensive = any(p.search(combined) for p in _RESOURCE_INTENSIVE_PATTERNS)

            if not is_intensive:
                continue

            has_timeout = bool(param_names_lower & TIMEOUT_PARAM_NAMES)

            if not has_timeout:
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
                            f"Resource-intensive tool '{tool_name}' has no timeout or "
                            f"duration limit parameter. Without bounded execution time, "
                            f"this tool could run indefinitely, consuming server resources "
                            f"and enabling denial-of-service attacks."
                        ),
                        evidence=f"tool={tool_name}, timeout_params=none",
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
                        f"All resource-intensive tools across {len(snapshot.tools)} "
                        f"tool(s) have timeout or duration limit parameters."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
