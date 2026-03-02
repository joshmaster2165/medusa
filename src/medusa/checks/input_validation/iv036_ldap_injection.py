"""IV036: LDAP Injection Parameters.

Detects tool parameters with LDAP-related names that lack input validation constraints.
Unvalidated LDAP parameters allow attackers to inject malicious LDAP filter expressions,
modify directory queries, and exfiltrate or manipulate directory service data.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_LDAP_PARAM_NAMES: set[str] = {
    "ldap",
    "dn",
    "distinguished_name",
    "filter",
    "ldap_filter",
    "base_dn",
    "search_base",
    "bind_dn",
    "ldap_query",
    "directory",
}


class LdapInjectionCheck(BaseCheck):
    """LDAP Injection Parameters."""

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
            input_schema: dict | None = tool.get("inputSchema")

            if not input_schema or not isinstance(input_schema, dict):
                continue

            properties: dict = input_schema.get("properties", {})
            if not isinstance(properties, dict):
                continue

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue

                lower_name = param_name.lower().strip()
                is_match = lower_name in _LDAP_PARAM_NAMES or any(
                    kw in lower_name for kw in _LDAP_PARAM_NAMES
                )
                if not is_match:
                    continue

                if param_def.get("type") != "string":
                    continue

                has_pattern = bool(param_def.get("pattern"))
                has_enum = bool(param_def.get("enum"))

                if has_pattern or has_enum:
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
                        resource_name=f"{tool_name}.{param_name}",
                        status_extended=(
                            f"Tool '{tool_name}' has LDAP-related parameter '{param_name}' "
                            f"without input validation constraints (no pattern or enum). "
                            f"Attackers can inject LDAP filter expressions to manipulate "
                            f"directory queries."
                        ),
                        evidence=(f"param={param_name}, type=string, pattern=N/A, enum=N/A"),
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
                        f"No LDAP injection risks detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
