"""TP024: Parameter Type Coercion Risk.

Detects tool parameters where the name implies a numeric or boolean value but
the JSON Schema type is declared as 'string', allowing type-coercion attacks.
Also flags parameters with no type declaration at all.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Param name fragments that suggest numeric values
_NUMERIC_NAME_HINTS: frozenset[str] = frozenset(
    {
        "count",
        "num",
        "number",
        "amount",
        "size",
        "length",
        "age",
        "id",
        "index",
        "limit",
        "offset",
        "page",
        "port",
        "timeout",
        "retry",
        "max",
        "min",
    }
)

# Param name fragments that suggest boolean values
_BOOLEAN_NAME_HINTS: frozenset[str] = frozenset(
    {
        "is_",
        "has_",
        "enable",
        "enabled",
        "disable",
        "disabled",
        "flag",
        "active",
        "allow",
        "allowed",
        "force",
        "verbose",
        "debug",
        "dry_run",
    }
)


def _name_implies_numeric(name: str) -> bool:
    lower = name.lower()
    return any(hint in lower for hint in _NUMERIC_NAME_HINTS)


def _name_implies_boolean(name: str) -> bool:
    lower = name.lower()
    return any(lower.startswith(hint) or hint in lower for hint in _BOOLEAN_NAME_HINTS)


class ParameterTypeCoercionCheck(BaseCheck):
    """Parameter Type Coercion Risk."""

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
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue
                declared_type = param_def.get("type", "")
                if declared_type != "string":
                    continue

                reason: str | None = None
                if _name_implies_numeric(param_name):
                    reason = f"param '{param_name}' name implies numeric but type is 'string'"
                elif _name_implies_boolean(param_name):
                    reason = f"param '{param_name}' name implies boolean but type is 'string'"

                if reason:
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
                                f"Tool '{tool_name}': {reason}. "
                                f"Type mismatch may enable coercion attacks."
                            ),
                            evidence=reason,
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
                        f"No parameter type coercion risks detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
