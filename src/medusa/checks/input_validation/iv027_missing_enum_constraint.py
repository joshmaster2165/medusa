"""IV027: Missing Enum Constraint on Action Parameters.

Detects action, operation, or type parameters that accept free-form strings instead of being
restricted to an enumerated set of valid values. Parameters that determine the tool's behaviour
mode should use enum constraints to prevent unexpected operations.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Parameter names that should be enum-constrained because they determine the operation mode
_ACTION_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "action",
        "operation",
        "op",
        "mode",
        "type",
        "method",
        "command_type",
        "request_type",
        "event_type",
        "operation_type",
    }
)

# Descriptions that imply a specific set of valid options
_OPTIONS_RE = re.compile(
    r"(one of|must be|valid values?|allowed values?|options?:)",
    re.IGNORECASE,
)


class MissingEnumConstraintCheck(BaseCheck):
    """Missing Enum Constraint on Action Parameters."""

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

                if param_def.get("type") != "string":
                    continue

                normalised = param_name.lower().strip()
                param_desc: str = param_def.get("description", "")

                name_match = normalised in _ACTION_PARAM_NAMES
                desc_match = bool(param_desc and _OPTIONS_RE.search(param_desc))

                if not name_match and not desc_match:
                    continue

                has_enum = bool(param_def.get("enum"))
                if has_enum:
                    continue

                reason = (
                    f"parameter name '{param_name}' implies an operation mode selector"
                    if name_match
                    else "description mentions specific options but no enum is defined"
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
                            f"Tool '{tool_name}' parameter '{param_name}' should be "
                            f"enum-constrained: {reason}. "
                            f"Free-form strings allow unexpected operation modes."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, enum=N/A, "
                            f"description={param_desc!r:.80}"
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
                        f"All action/mode parameters have enum constraints "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
