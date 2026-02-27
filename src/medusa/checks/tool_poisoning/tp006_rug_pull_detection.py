"""TP-006: Rug Pull Detection — Tool Definition Drift.

Detects when the server does not advertise the ``toolListChanged`` notification
capability.  Without it, tool definitions can change silently between sessions,
enabling a malicious server to present benign tools during review and then swap
them for harmful ones — a rug-pull attack.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class RugPullDetectionCheck(BaseCheck):
    """Rug Pull Detection — Tool Definition Drift."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        capabilities = snapshot.capabilities or {}
        # The MCP spec places notification support under capabilities["tools"]
        tools_cap = capabilities.get("tools", {})
        has_notification = False
        if isinstance(tools_cap, dict):
            has_notification = bool(tools_cap.get("listChanged", False))

        if not has_notification:
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
                        "Server does not advertise the 'toolListChanged' "
                        "notification capability. Tool definitions may change "
                        "silently between sessions (rug-pull risk)."
                    ),
                    evidence=(
                        f"capabilities.tools.listChanged is absent or false. "
                        f"Observed capabilities: {capabilities}"
                    ),
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
                        "Server advertises 'toolListChanged' notification "
                        "capability; clients can detect tool definition changes."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
