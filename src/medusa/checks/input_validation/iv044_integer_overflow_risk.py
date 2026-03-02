"""IV044: Integer Overflow Risk.

Detects integer parameters with maximum values exceeding safe integer ranges.
JSON numbers are IEEE 754 doubles, so integers above 2^53 - 1 lose precision.
On 32-bit systems, values above 2^31 - 1 can cause overflow.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Number.MAX_SAFE_INTEGER in JavaScript / JSON
_MAX_SAFE_INTEGER: int = 9007199254740991
_MIN_SAFE_INTEGER: int = -9007199254740991


class IntegerOverflowRiskCheck(BaseCheck):
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

            if not input_schema or not isinstance(
                input_schema, dict
            ):
                continue

            properties: dict = input_schema.get("properties", {})
            if not isinstance(properties, dict):
                continue

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue

                if param_def.get("type") != "integer":
                    continue

                max_val = param_def.get("maximum")
                min_val = param_def.get("minimum")

                exceeds_max = (
                    max_val is not None
                    and max_val > _MAX_SAFE_INTEGER
                )
                exceeds_min = (
                    min_val is not None
                    and min_val < _MIN_SAFE_INTEGER
                )

                if not exceeds_max and not exceeds_min:
                    continue

                issues = []
                if exceeds_max:
                    issues.append(
                        f"maximum={max_val} > "
                        f"{_MAX_SAFE_INTEGER}"
                    )
                if exceeds_min:
                    issues.append(
                        f"minimum={min_val} < "
                        f"{_MIN_SAFE_INTEGER}"
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
                        resource_name=(
                            f"{tool_name}.{param_name}"
                        ),
                        status_extended=(
                            f"Tool '{tool_name}' integer "
                            f"parameter '{param_name}' has "
                            f"bounds exceeding safe integer "
                            f"range: {', '.join(issues)}. "
                            f"Values beyond this range lose "
                            f"precision in JSON and may "
                            f"overflow on 32-bit systems."
                        ),
                        evidence=(
                            f"param={param_name}, "
                            f"type=integer, "
                            f"minimum={min_val}, "
                            f"maximum={max_val}, "
                            f"safe_range="
                            f"[{_MIN_SAFE_INTEGER}, "
                            f"{_MAX_SAFE_INTEGER}]"
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
                        f"All integer parameters have safe "
                        f"bounds across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
