"""TF-001: Data Leak Flow Detection.

Detects when a server exposes a combination of tools that together enable
a data leak flow: untrusted input → private data access → public output sink.

Inspired by Snyk agent-scan's TF001 toxic flow analysis, implemented as
local static analysis using Medusa's tool classifier.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.tool_classifier import classify_tools


class DataLeakFlowCheck(BaseCheck):
    """Detect data leak flows from dangerous tool combinations."""

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
        private = {name for name, lbl in labels.items() if lbl.private_data > 0}
        sinks = {name for name, lbl in labels.items() if lbl.public_sink > 0}

        # Data leak flow requires all three categories present
        if untrusted and private and sinks:
            flow_desc = (
                f"Untrusted input: {', '.join(sorted(untrusted)[:5])} → "
                f"Private data: {', '.join(sorted(private)[:5])} → "
                f"Public sink: {', '.join(sorted(sinks)[:5])}"
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
                        f"Server exposes a data leak flow: tools accepting "
                        f"untrusted input ({len(untrusted)}), accessing private "
                        f"data ({len(private)}), and sending to external sinks "
                        f"({len(sinks)}) are all present. An attacker could chain "
                        f"these to exfiltrate sensitive data."
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
                        f"No data leak flow detected across {len(snapshot.tools)} tool(s). "
                        f"Server does not expose all three required categories "
                        f"(untrusted input, private data, public sink)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
