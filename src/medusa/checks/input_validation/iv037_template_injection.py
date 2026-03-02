"""IV037: Server-Side Template Injection.

Detects tool parameters with template-related names or descriptions that lack input
validation constraints. Unvalidated template parameters allow attackers to inject
template directives that execute arbitrary code on the server through template engines
like Jinja2, Mustache, or Handlebars.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_TEMPLATE_PARAM_NAMES: set[str] = {
    "template",
    "render",
    "jinja",
    "mustache",
    "handlebars",
    "format_string",
    "tpl",
    "layout",
    "view",
    "template_string",
    "format",
    "markup",
}

_TEMPLATE_DESC_RE = re.compile(r"template|render|format\s*string", re.IGNORECASE)


class TemplateInjectionCheck(BaseCheck):
    """Server-Side Template Injection."""

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

                # Check if param name matches or description mentions templates
                name_match = param_name.lower().strip() in _TEMPLATE_PARAM_NAMES
                desc = param_def.get("description", "")
                desc_match = bool(_TEMPLATE_DESC_RE.search(desc)) if desc else False

                if not name_match and not desc_match:
                    continue

                has_pattern = bool(param_def.get("pattern"))
                has_enum = bool(param_def.get("enum"))

                if has_pattern or has_enum:
                    continue

                match_reason = "name" if name_match else "description"
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
                            f"Tool '{tool_name}' has template-related parameter "
                            f"'{param_name}' (matched by {match_reason}) without input "
                            f"validation constraints. Attackers can inject template "
                            f"directives for server-side code execution."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern=N/A, enum=N/A, "
                            f"matched_by={match_reason}"
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
                        f"No template injection risks detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
