"""TP018: JSON Injection in Parameter Defaults.

Detects serialized JSON objects embedded in parameter default values. Complex JSON defaults can
encode instructions, configuration overrides, or nested command structures that alter tool
behaviour in ways not apparent from the schema surface.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.text_analysis import find_injection_phrases


def _is_suspicious_default(value: object) -> str | None:
    """Return a description if the default value looks like an injection payload."""
    if isinstance(value, str):
        # Check for embedded JSON object/array strings
        stripped = value.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            try:
                json.loads(stripped)
                return f"String default contains embedded JSON: {stripped[:80]}"
            except json.JSONDecodeError:
                pass
        # Check for injection phrases in string defaults
        phrases = find_injection_phrases(stripped)
        if phrases:
            return f"String default contains injection phrases: {'; '.join(phrases[:3])}"
    elif isinstance(value, dict) and value:
        return f"Object default with keys: {list(value.keys())[:5]}"
    return None


class JsonInjectionInDefaultsCheck(BaseCheck):
    """JSON Injection in Parameter Defaults."""

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
                if "default" not in param_def:
                    continue
                reason = _is_suspicious_default(param_def["default"])
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
                                f"Parameter '{param_name}' of tool '{tool_name}' "
                                f"has a suspicious default value: {reason}"
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
                        f"No JSON injection in parameter defaults detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
