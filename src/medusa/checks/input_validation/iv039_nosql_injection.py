"""IV039: NoSQL Injection Parameters.

Detects tool parameters with NoSQL or document database-related names that lack input
validation constraints. Unvalidated NoSQL parameters allow attackers to inject query
operators and manipulate database queries to bypass authentication, exfiltrate data,
or modify records.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_NOSQL_PARAM_NAMES: set[str] = {
    "mongo",
    "mongodb",
    "nosql",
    "collection",
    "aggregate",
    "pipeline",
    "match_query",
    "lookup",
    "document",
    "selector",
    "mongo_query",
    "bson",
}


class NosqlInjectionCheck(BaseCheck):
    """NoSQL Injection Parameters."""

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

                if param_name.lower().strip() not in _NOSQL_PARAM_NAMES:
                    continue

                param_type = param_def.get("type", "")
                if param_type not in ("string", "object"):
                    continue

                has_pattern = bool(param_def.get("pattern"))
                has_enum = bool(param_def.get("enum"))

                if param_type == "string":
                    if has_pattern or has_enum:
                        continue
                elif param_type == "object":
                    add_props = param_def.get(
                        "additionalProperties"
                    )
                    if add_props is False:
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
                            f"Tool '{tool_name}' has NoSQL-related parameter "
                            f"'{param_name}' (type: {param_type}) without input "
                            f"validation constraints. Attackers can inject query "
                            f"operators to manipulate database queries."
                        ),
                        evidence=(
                            f"param={param_name}, type={param_type}, "
                            f"pattern=N/A, enum=N/A"
                        ),
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
                        f"No NoSQL injection risks detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
