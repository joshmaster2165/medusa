"""IV011: Regular Expression DoS (ReDoS).

Detects tool parameters used in regular expression matching without complexity limits. User-
controlled input in regex patterns or matched against vulnerable regex patterns can cause
catastrophic backtracking, leading to denial of service.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Detect catastrophic backtracking patterns: nested quantifiers like (a+)+, (a*)*,  (.+)+
_REDOS_PATTERNS = [
    re.compile(r"\([^)]*[+*][^)]*\)[+*]"),  # (x+)+ or (x*)* style
    re.compile(r"\([^)]*\)\{[0-9]+,[0-9]*\}\*"),  # (x){n,}* style
    re.compile(r"\([^)]*\+[^)]*\)\+"),  # (a+b+)+ style
]


class RegexDosCheck(BaseCheck):
    """Regular Expression DoS (ReDoS)."""

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

                pattern_val: str = param_def.get("pattern", "")
                if not pattern_val:
                    continue

                # Check if pattern contains catastrophic backtracking constructs
                is_catastrophic = any(p.search(pattern_val) for p in _REDOS_PATTERNS)
                if not is_catastrophic:
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
                            f"Tool '{tool_name}' parameter '{param_name}' uses a regex pattern "
                            f"with nested quantifiers that may cause catastrophic backtracking. "
                            f"Attackers can submit crafted input to cause ReDoS denial of service."
                        ),
                        evidence=(
                            f"param={param_name}, pattern={pattern_val!r} "
                            f"(contains nested quantifiers)"
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
                        f"No catastrophic regex patterns detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
