"""IV017: Null Byte Injection Risk.

Detects tool parameters that may be vulnerable to null byte injection. Null bytes (\\x00) in
file paths or strings can truncate processing in C-based libraries, causing the application to
operate on a different resource than validated.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# A pattern blocks null bytes if it explicitly excludes \\x00 or %00
_NULL_BLOCK_RE = re.compile(r"\\x00|\\0|%00|\[\\x00\]|\\u0000")


class NullByteInjectionCheck(BaseCheck):
    """Null Byte Injection Risk."""

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
                if pattern_val and _NULL_BLOCK_RE.search(pattern_val):
                    continue
                # A strict ASCII-only pattern inherently blocks null bytes
                if pattern_val and re.search(r"\^?\[a-zA-Z", pattern_val):
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
                            f"block null byte characters (\\x00, %00). "
                            f"Null bytes can truncate file paths and bypass security checks "
                            f"in C-based libraries."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={param_def.get('pattern', 'N/A')}, "
                            f"no null byte exclusion detected"
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
                        f"No null byte injection risks detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
