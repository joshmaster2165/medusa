"""PMT004: Prompt Template Injection.

Detects MCP prompt templates where the template syntax itself can be exploited to inject
additional template directives. If the templating engine processes user input as template code
rather than literal text, attackers can execute arbitrary template operations.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_TEMPLATE_SYNTAX_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\{\{.*?\}\}"),  # Jinja2 / Handlebars / Mustache
    re.compile(r"\{%.*?%\}"),  # Jinja2 block tags
    re.compile(r"\$\{.*?\}"),  # JavaScript template literals / shell
    re.compile(r"#\{.*?\}"),  # Ruby interpolation
]


class PromptTemplateInjectionCheck(BaseCheck):
    """Prompt Template Injection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.prompts:
            return findings

        for prompt in snapshot.prompts:
            prompt_name = prompt.get("name", "<unnamed>")
            arguments = prompt.get("arguments", [])

            for arg in arguments:
                arg_name = arg.get("name", "<unnamed>")
                arg_desc = arg.get("description", "")
                if not arg_desc:
                    continue

                hits: list[str] = []
                for pattern in _TEMPLATE_SYNTAX_PATTERNS:
                    for m in pattern.finditer(arg_desc):
                        hits.append(m.group()[:80])

                if hits:
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="prompt",
                            resource_name=f"{prompt_name}.{arg_name}",
                            status_extended=(
                                f"Prompt '{prompt_name}' argument '{arg_name}' "
                                f"description contains template injection syntax: "
                                f"{'; '.join(hits[:3])}"
                            ),
                            evidence="; ".join(hits[:5]),
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        if not findings and snapshot.prompts:
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
                        f"No template injection syntax detected across "
                        f"{len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
