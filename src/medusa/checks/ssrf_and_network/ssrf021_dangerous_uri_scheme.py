"""SSRF021: Dangerous URI Scheme References in Tool Metadata.

Detects references to dangerous URI schemes such as file://, gopher://,
dict://, ftp://, ldap://, and tftp:// in tool descriptions, parameter
descriptions, or default values. These schemes can enable local file access,
protocol-level attacks, or server-side request forgery exploits.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.ssrf import DANGEROUS_SCHEMES

_DANGEROUS_SCHEME_PATTERN: re.Pattern[str] = re.compile(
    r"\b(" + "|".join(re.escape(s) for s in sorted(DANGEROUS_SCHEMES)) + r")://",
    re.IGNORECASE,
)


class DangerousUriSchemeCheck(BaseCheck):
    """Dangerous URI Scheme References in Tool Metadata."""

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
            # Combine tool description + all parameter descriptions + string defaults
            parts: list[str] = [tool.get("description", "") or ""]
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            for param_def in properties.values():
                if isinstance(param_def, dict):
                    parts.append(param_def.get("description", "") or "")
                    default = param_def.get("default")
                    if isinstance(default, str):
                        parts.append(default)
            all_text = " ".join(parts)

            if not all_text.strip():
                continue

            matched: list[str] = _DANGEROUS_SCHEME_PATTERN.findall(all_text)

            if matched:
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
                            f"Tool '{tool_name}' references dangerous URI "
                            f"schemes: {', '.join(f'{s}://' for s in matched[:3])}. "
                            f"These may enable SSRF or local file access."
                        ),
                        evidence=(f"dangerous_schemes={[f'{s}://' for s in matched[:5]]}"),
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
                        f"No dangerous URI scheme references detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
