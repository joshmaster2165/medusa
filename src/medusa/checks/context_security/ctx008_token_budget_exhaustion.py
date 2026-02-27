"""CTX008: Token Budget Exhaustion.

Detects MCP tools that return excessively large responses that consume a disproportionate share
of the available token budget. Token budget exhaustion degrades LLM performance and increases
costs.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# A single tool description exceeding this is suspicious for token flooding
_TOOL_DESC_CHAR_LIMIT = 5_000
# Number of tools with oversized descriptions before we flag
_OVERSIZED_TOOL_THRESHOLD = 3


class TokenBudgetExhaustionCheck(BaseCheck):
    """Token Budget Exhaustion."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        oversized: list[str] = []
        for tool in snapshot.tools:
            desc = tool.get("description") or ""
            if len(desc) > _TOOL_DESC_CHAR_LIMIT:
                oversized.append(f"tool '{tool.get('name', '?')}' ({len(desc):,} chars)")

        if len(oversized) >= _OVERSIZED_TOOL_THRESHOLD:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' has {len(oversized)} tool(s) with "
                        f"descriptions exceeding {_TOOL_DESC_CHAR_LIMIT:,} chars each. "
                        f"This may exhaust the LLM token budget."
                    ),
                    evidence="; ".join(oversized[:5]),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
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
                        f"Server '{snapshot.server_name}' tool descriptions are within "
                        f"token-budget limits ({len(oversized)} oversized tool(s) found, "
                        f"threshold is {_OVERSIZED_TOOL_THRESHOLD})."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
