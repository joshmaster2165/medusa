"""IV035: HTML Injection Risk.

Detects tool parameters whose output may be rendered in HTML contexts without proper escaping.
Parameters containing HTML tags or entities can inject content into web pages, enabling cross-
site scripting and content spoofing attacks.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# A pattern blocks HTML if it explicitly excludes < > & characters
_HTML_BLOCK_RE = re.compile(r"<|>|&amp|\\x3[cC]|\\u003[cC]|\[<>\]")
# A safe pattern uses only alphanumeric ranges (implicitly excludes HTML chars)
_ALPHA_ONLY_RE = re.compile(r"^\^?\[a-z", re.IGNORECASE)


class HtmlInjectionCheck(BaseCheck):
    """HTML Injection Risk."""

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

                pattern_val: str = param_def.get("pattern", "")
                has_enum = bool(param_def.get("enum"))

                if has_enum:
                    continue
                if pattern_val and _HTML_BLOCK_RE.search(pattern_val):
                    continue
                if pattern_val and _ALPHA_ONLY_RE.match(pattern_val):
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
                            f"Tool '{tool_name}' string parameter '{param_name}' does not "
                            f"block HTML special characters (<, >, &). "
                            f"Attacker-controlled HTML tags can inject scripts or spoof content."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={param_def.get('pattern', 'N/A')}, "
                            f"no HTML character exclusion detected"
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
                        f"No HTML injection risks detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
