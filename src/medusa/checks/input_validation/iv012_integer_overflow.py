"""IV012: Integer Overflow Risk.

Detects numeric tool parameters without explicit range constraints (minimum/maximum values).
Unconstrained integer parameters can trigger integer overflow, underflow, or truncation
vulnerabilities in server-side processing.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class IntegerOverflowCheck(BaseCheck):
    """Integer Overflow Risk."""

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
                if param_type not in ("integer", "number"):
                    continue

                has_minimum = "minimum" in param_def or "exclusiveMinimum" in param_def
                has_maximum = "maximum" in param_def or "exclusiveMaximum" in param_def

                if has_minimum and has_maximum:
                    continue

                missing = []
                if not has_minimum:
                    missing.append("minimum")
                if not has_maximum:
                    missing.append("maximum")

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
                            f"Tool '{tool_name}' numeric parameter '{param_name}' "
                            f"(type={param_type}) is missing range constraints: "
                            f"{', '.join(missing)}. "
                            f"Unbounded numeric inputs may cause integer overflow or underflow."
                        ),
                        evidence=(
                            f"param={param_name}, type={param_type}, "
                            f"minimum={param_def.get('minimum', 'N/A')}, "
                            f"maximum={param_def.get('maximum', 'N/A')}"
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
                        f"All numeric parameters have range constraints defined "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
