"""IV022: Unsafe Deserialization Risk.

Detects tool parameters that suggest object deserialization from user input. Parameters
accepting serialized objects (pickle, Java serialization, YAML load, PHP unserialize) can
trigger arbitrary code execution when attacker-controlled data is deserialized.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class DeserializationRiskCheck(BaseCheck):
    """Unsafe Deserialization Risk."""

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

                # Flag object-typed params with no schema (additionalProperties not False)
                if param_def.get("type") != "object":
                    continue

                has_properties_schema = bool(param_def.get("properties"))
                additional = param_def.get("additionalProperties")
                is_locked = additional is False

                if has_properties_schema and is_locked:
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
                            f"Tool '{tool_name}' object parameter '{param_name}' accepts "
                            f"arbitrary object structure "
                            f"(no schema or additionalProperties:false). "
                            f"Attacker-controlled objects passed to deserializers can trigger "
                            f"remote code execution."
                        ),
                        evidence=(
                            f"param={param_name}, type=object, "
                            f"properties={'defined' if has_properties_schema else 'N/A'}, "
                            f"additionalProperties={additional!r}"
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
                        f"No unsafe deserialization parameters detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
