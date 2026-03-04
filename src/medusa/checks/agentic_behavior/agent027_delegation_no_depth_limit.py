"""AGENT027: Delegation Tools Without Depth Limits.

Detects tools with delegation keywords (delegate, orchestrate, chain, spawn,
relay, proxy) in their name or description without depth or iteration limits
in the server configuration. Delegation tools without bounds create infinite
delegation chain risks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.agentic import AGENT_SAFETY_CONFIG_KEYS, DELEGATION_KEYWORDS


class DelegationNoDepthLimitCheck(BaseCheck):
    """Delegation Tools Without Depth Limits."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Check if server config has safety keys
        config_str = str(snapshot.config_raw).lower() if snapshot.config_raw else ""
        has_safety_config = any(key in config_str for key in AGENT_SAFETY_CONFIG_KEYS)

        if has_safety_config:
            # Safety configuration exists — no issue
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
                            f"No delegation tools without depth limits "
                            f"detected across {len(snapshot.tools)} tool(s)."
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )
            return findings

        # Iterate tools and check for delegation keywords
        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            description: str = (tool.get("description", "") or "").lower()
            tool_name_lower = tool_name.lower()

            is_delegation = any(
                kw in tool_name_lower or kw in description for kw in DELEGATION_KEYWORDS
            )

            if is_delegation:
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
                            f"Tool '{tool_name}' has delegation capabilities "
                            f"but server lacks depth/iteration limits. No "
                            f"safety configuration keys ("
                            f"{', '.join(sorted(AGENT_SAFETY_CONFIG_KEYS)[:3])}"
                            f", ...) found."
                        ),
                        evidence=(f"delegation_tool={tool_name}, missing_safety_config=True"),
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
                        f"No delegation tools without depth limits "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
