"""TP022: TOCTOU in Tool Definitions.

Detects time-of-check-time-of-use vulnerabilities where tool definitions can change between the
listing phase (when tools are reviewed) and the invocation phase (when tools are executed). A
malicious server can present safe definitions during listing but swap them at invocation time.

Heuristic: flag tools that have BOTH read/check-style params AND write/execute-style params,
suggesting the tool may operate on a different target at execution time than was checked.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_CHECK_PARAMS: list[re.Pattern[str]] = [
    re.compile(r"check", re.IGNORECASE),
    re.compile(r"verify", re.IGNORECASE),
    re.compile(r"validate", re.IGNORECASE),
    re.compile(r"read", re.IGNORECASE),
    re.compile(r"source", re.IGNORECASE),
]

_USE_PARAMS: list[re.Pattern[str]] = [
    re.compile(r"write", re.IGNORECASE),
    re.compile(r"execute", re.IGNORECASE),
    re.compile(r"target", re.IGNORECASE),
    re.compile(r"destination", re.IGNORECASE),
    re.compile(r"output", re.IGNORECASE),
    re.compile(r"delete", re.IGNORECASE),
]


class TimeOfCheckTimeOfUseCheck(BaseCheck):
    """TOCTOU in Tool Definitions."""

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
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = list(properties.keys())

            check_hits = [p for p in param_names if any(pat.search(p) for pat in _CHECK_PARAMS)]
            use_hits = [p for p in param_names if any(pat.search(p) for pat in _USE_PARAMS)]

            if check_hits and use_hits:
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
                            f"Tool '{tool_name}' has both read/check params "
                            f"({check_hits[:3]}) and write/execute params "
                            f"({use_hits[:3]}), suggesting TOCTOU risk."
                        ),
                        evidence=(
                            f"check-side params: {check_hits[:3]}; use-side params: {use_hits[:3]}"
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
                        f"No TOCTOU indicators detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
