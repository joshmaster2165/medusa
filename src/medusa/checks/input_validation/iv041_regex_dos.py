"""IV041: Regex Denial of Service (ReDoS).

Detects tool parameters that have a pattern constraint but no maxLength limit.
Without a length limit, a long input can cause catastrophic backtracking on
complex regexes with nested quantifiers.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Detect nested quantifiers that cause catastrophic backtracking
# Patterns like (a+)+, (a*)+, (a|a)*, (a+)*, etc.
_CATASTROPHIC_RE = re.compile(r"(\(.+[+*]\))[+*]")


class RegexDosCheck(BaseCheck):
    """Regex Denial of Service (ReDoS)."""

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

            if not input_schema or not isinstance(
                input_schema, dict
            ):
                continue

            properties: dict = input_schema.get("properties", {})
            if not isinstance(properties, dict):
                continue

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue

                if param_def.get("type") != "string":
                    continue

                pattern_val = param_def.get("pattern", "")
                if not pattern_val:
                    continue

                max_length = param_def.get("maxLength")
                if max_length is not None:
                    continue

                # Check for catastrophic backtracking constructs
                if not _CATASTROPHIC_RE.search(pattern_val):
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
                        resource_name=(
                            f"{tool_name}.{param_name}"
                        ),
                        status_extended=(
                            f"Tool '{tool_name}' parameter "
                            f"'{param_name}' has a pattern with "
                            f"nested quantifiers but no maxLength "
                            f"constraint. Long inputs can cause "
                            f"catastrophic backtracking."
                        ),
                        evidence=(
                            f"param={param_name}, "
                            f"pattern={pattern_val}, "
                            f"maxLength=N/A, "
                            f"nested_quantifier=detected"
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
                        f"No ReDoS risks detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
