"""IV025: Template Literal Injection.

Detects tool parameters used in JavaScript template literals or equivalent constructs without
sanitization. User input interpolated into template literals can execute arbitrary JavaScript
expressions via ${...} syntax.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.schema import TEMPLATE_PARAM_NAMES

# Pattern that blocks ${...} template literal expressions
_TEMPLATE_BLOCK_RE = re.compile(r"\$\{|\$\\{|dollar.*brace", re.IGNORECASE)

# Additional names suggesting template literal usage beyond TEMPLATE_PARAM_NAMES
_TEMPLATE_LITERAL_NAMES: frozenset[str] = TEMPLATE_PARAM_NAMES | frozenset(
    {"body", "content", "text", "message_body", "email_body", "html_content"}
)


class TemplateLiteralInjectionCheck(BaseCheck):
    """Template Literal Injection."""

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

                if param_name.lower().strip() not in _TEMPLATE_LITERAL_NAMES:
                    continue

                pattern_val: str = param_def.get("pattern", "")
                has_enum = bool(param_def.get("enum"))

                if has_enum:
                    continue
                if pattern_val and _TEMPLATE_BLOCK_RE.search(pattern_val):
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
                            f"Tool '{tool_name}' template-related parameter '{param_name}' "
                            f"does not block template literal sequences (${{...}}). "
                            f"Attacker-controlled backtick expressions can execute arbitrary "
                            f"JavaScript when interpolated."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={param_def.get('pattern', 'N/A')}, "
                            f"no ${{...}} exclusion detected"
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
                        f"No template literal injection risks detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
