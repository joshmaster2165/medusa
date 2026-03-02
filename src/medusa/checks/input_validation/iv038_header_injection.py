"""IV038: HTTP Header Injection (CRLF).

Detects tool parameters with HTTP header-related names that lack CRLF protection.
Without rejecting carriage return and line feed characters, attackers can inject
additional HTTP headers, enabling response splitting, session fixation, and cache
poisoning attacks.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HEADER_PARAM_NAMES: set[str] = {
    "header",
    "headers",
    "http_header",
    "user_agent",
    "referer",
    "cookie",
    "authorization",
    "content_type",
    "x_forwarded_for",
    "accept",
    "host",
}

# Pattern that blocks CRLF characters - look for explicit rejection of \r or \n
_CRLF_BLOCK_RE = re.compile(r"\\r|\\n|\\x0[aAdD]|\\u000[aAdD]|\[^[^\]]*\\r|\\n")


class HeaderInjectionCheck(BaseCheck):
    """HTTP Header Injection (CRLF)."""

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

                if param_name.lower().strip() not in _HEADER_PARAM_NAMES:
                    continue

                if param_def.get("type") != "string":
                    continue

                has_enum = bool(param_def.get("enum"))
                if has_enum:
                    continue

                # Check if the pattern explicitly blocks CRLF
                pattern_val: str = param_def.get("pattern", "")
                if pattern_val and _CRLF_BLOCK_RE.search(pattern_val):
                    continue

                # A printable-ASCII-only pattern also blocks CRLF
                if pattern_val and re.search(r"\^?\[\\x20-\\x7[eE]\]", pattern_val):
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
                            f"Tool '{tool_name}' has HTTP header parameter "
                            f"'{param_name}' without CRLF protection. Attackers "
                            f"can inject carriage return and line feed characters "
                            f"to perform HTTP response splitting attacks."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={pattern_val or 'N/A'}, "
                            f"no CRLF rejection detected"
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
                        f"No HTTP header injection risks detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
