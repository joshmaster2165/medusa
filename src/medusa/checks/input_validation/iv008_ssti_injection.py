"""IV008: Server-Side Template Injection Risk.

Detects tool parameters that may be passed to server-side template engines without sanitization.
Parameters named 'template', 'content', 'message_body', or similar that accept unconstrained
strings can enable template injection in engines like Jinja2, Twig, or Handlebars.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.schema import TEMPLATE_PARAM_NAMES

# Pattern that would block common SSTI delimiters: {{ }}, {% %}, ${ }
_SSTI_BLOCK_RE = re.compile(r"\\\{|\{\{|\{%|\$\{|\[%")


class SstiInjectionCheck(BaseCheck):
    """Server-Side Template Injection Risk."""

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

                if param_name.lower().strip() not in TEMPLATE_PARAM_NAMES:
                    continue

                pattern_val = param_def.get("pattern", "")
                has_enum = bool(param_def.get("enum"))

                # Safe if enum-constrained or pattern blocks SSTI sequences
                if has_enum:
                    continue
                if pattern_val and _SSTI_BLOCK_RE.search(pattern_val):
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
                            f"Tool '{tool_name}' has template-related parameter '{param_name}' "
                            f"that does not block template injection sequences "
                            f"({{{{, {{%, ${{). Attacker-controlled input could execute "
                            f"arbitrary code via template engine injection."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={param_def.get('pattern', 'N/A')}, "
                            f"enum={param_def.get('enum', 'N/A')}"
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
                        f"No unconstrained SSTI-vulnerable parameters detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
