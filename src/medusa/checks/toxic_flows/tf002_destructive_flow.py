"""TF-002: Destructive Flow Detection.

Detects when a server exposes a combination of tools that together enable
a destructive flow: untrusted input → destructive action.

Inspired by Snyk agent-scan's TF002 toxic flow analysis, implemented as
local static analysis using Medusa's tool classifier.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.tool_classifier import classify_tools


class DestructiveFlowCheck(BaseCheck):
    """Detect destructive flows from dangerous tool combinations."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools or len(snapshot.tools) < 2:
            return findings

        labels = classify_tools(snapshot.tools)

        # Collect tools in each category
        untrusted = {name for name, lbl in labels.items() if lbl.untrusted_input > 0}
        destructive = {name for name, lbl in labels.items() if lbl.destructive > 0}

        # Destructive flow requires both categories present
        if untrusted and destructive:
            flow_desc = (
                f"Untrusted input: {', '.join(sorted(untrusted)[:5])} → "
                f"Destructive: {', '.join(sorted(destructive)[:5])}"
            )
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
                        f"Server exposes a destructive flow: tools accepting "
                        f"untrusted input ({len(untrusted)}) and performing "
                        f"destructive operations ({len(destructive)}) are both "
                        f"present. An attacker could inject malicious content "
                        f"to trigger destructive actions."
                    ),
                    evidence=flow_desc,
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
                        f"No destructive flow detected across {len(snapshot.tools)} tool(s). "
                        f"Server does not expose both untrusted input and destructive tools."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
