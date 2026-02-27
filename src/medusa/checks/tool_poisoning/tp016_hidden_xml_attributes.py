"""TP016: Hidden XML Attributes in Descriptions.

Detects XML attributes embedded in tool descriptions that smuggle hidden instructions to the
LLM. Attributes such as data-instruction, aria-label, or custom attributes within XML/HTML tags
can carry payloads that are processed by the LLM but not visible in rendered UI output.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Suspicious HTML/XML attributes that may carry hidden payloads
_SUSPICIOUS_ATTR_PATTERN: re.Pattern[str] = re.compile(
    r"<[a-zA-Z][^>]*\s(?:onclick|onerror|onload|style|src|href|data-\w+|"
    r"aria-\w+|x-\w+|ng-\w+)\s*=",
    re.IGNORECASE,
)


class HiddenXmlAttributesCheck(BaseCheck):
    """Hidden XML Attributes in Descriptions."""

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
            description: str = tool.get("description", "")

            if not description:
                continue

            hits = [m.group()[:120] for m in _SUSPICIOUS_ATTR_PATTERN.finditer(description)]
            if hits:
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
                            f"Tool '{tool_name}' description contains XML/HTML "
                            f"tags with suspicious attributes that may carry "
                            f"hidden instructions: {'; '.join(hits[:3])}"
                        ),
                        evidence="; ".join(hits[:5]),
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
                        f"No hidden XML attributes detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
