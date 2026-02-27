"""IV007: NoSQL Injection Risk.

Detects tool parameters suggesting MongoDB or other NoSQL query construction without validation.
Parameters accepting JSON objects or query operators like $gt, $regex, or $where enable NoSQL
injection attacks that bypass authentication and access controls.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.schema import NOSQL_PARAM_NAMES


class NosqlInjectionCheck(BaseCheck):
    """NoSQL Injection Risk."""

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

                param_type = param_def.get("type")
                normalised = param_name.lower().strip()

                # Flag NoSQL-named params without pattern/enum, or object-typed params
                # that could accept operators like $gt, $regex, $where
                name_match = normalised in NOSQL_PARAM_NAMES
                is_open_object = (
                    param_type == "object" and param_def.get("additionalProperties") is not False
                )

                if not name_match and not is_open_object:
                    continue

                has_pattern = bool(param_def.get("pattern"))
                has_enum = bool(param_def.get("enum"))
                has_schema = (
                    bool(param_def.get("properties"))
                    or param_def.get("additionalProperties") is False
                )

                if name_match and (has_pattern or has_enum):
                    continue
                if is_open_object and not name_match and has_schema:
                    continue

                reason = (
                    f"NoSQL-named parameter '{param_name}' lacks pattern/enum constraint"
                    if name_match
                    else (
                        f"Object-typed parameter '{param_name}' "
                        f"accepts NoSQL operators without schema"
                    )
                )

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
                            f"Tool '{tool_name}' parameter '{param_name}' is vulnerable to "
                            f"NoSQL injection. {reason}."
                        ),
                        evidence=(
                            f"param={param_name}, type={param_type}, "
                            f"pattern={param_def.get('pattern', 'N/A')}, "
                            f"enum={param_def.get('enum', 'N/A')}, "
                            f"additionalProperties={param_def.get('additionalProperties', 'N/A')}"
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
                        f"No unconstrained NoSQL injection parameters detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
