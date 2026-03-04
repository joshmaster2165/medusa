"""TP038: Hidden HTML/CSS Content in Tool Descriptions.

Detects HTML/CSS techniques that hide content from visual display in tool
or parameter descriptions, including display:none, visibility:hidden,
opacity:0, font-size:0, and the HTML hidden attribute. LLMs process the
hidden text even though users cannot see it, enabling steganographic
instruction hiding.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HIDDEN_CSS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r'style\s*=\s*["\'][^"\']*?display\s*:\s*none', re.IGNORECASE | re.DOTALL),
        "display:none",
    ),
    (
        re.compile(r'style\s*=\s*["\'][^"\']*?visibility\s*:\s*hidden', re.IGNORECASE | re.DOTALL),
        "visibility:hidden",
    ),
    (
        re.compile(r'style\s*=\s*["\'][^"\']*?opacity\s*:\s*0[^.\d]', re.IGNORECASE | re.DOTALL),
        "opacity:0",
    ),
    (
        re.compile(r'style\s*=\s*["\'][^"\']*?font-size\s*:\s*0', re.IGNORECASE | re.DOTALL),
        "font-size:0",
    ),
    (re.compile(r"<\w+[^>]+\bhidden\b[^>]*>", re.IGNORECASE), "hidden attribute"),
]


class HiddenHtmlCssContentCheck(BaseCheck):
    """Hidden HTML/CSS Content in Tool Descriptions."""

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
            # Combine tool description + all parameter descriptions
            parts: list[str] = [tool.get("description", "") or ""]
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            for param_def in properties.values():
                if isinstance(param_def, dict):
                    parts.append(param_def.get("description", "") or "")
            all_text = " ".join(parts)

            if not all_text.strip():
                continue

            matched: list[str] = []
            for pattern, label in _HIDDEN_CSS_PATTERNS:
                if pattern.search(all_text):
                    matched.append(label)

            if matched:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=(
                            f"Tool '{tool_name}' contains hidden HTML/CSS "
                            f"content techniques: {', '.join(matched[:3])}. "
                            f"Hidden content may contain injected instructions "
                            f"invisible to users."
                        ),
                        evidence=f"hidden_css_matches={matched}",
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
                        f"No hidden HTML/CSS content detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
