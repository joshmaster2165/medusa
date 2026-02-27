"""PRIV-002: Detect unrestricted network-access tools.

Identifies tools whose names match known network-operation patterns (HTTP,
fetch, download, upload, API call, etc.) and checks whether their schemas
enforce URL or domain allowlists. Unrestricted network tools enable SSRF,
data exfiltration, and lateral movement.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import NETWORK_TOOL_PATTERNS

# Parameter names that typically hold URLs or hostnames
_URL_PARAM_NAMES: set[str] = {
    "url",
    "uri",
    "endpoint",
    "host",
    "hostname",
    "domain",
    "address",
    "target_url",
    "request_url",
    "base_url",
    "api_url",
    "webhook_url",
    "callback_url",
    "destination",
    "remote",
}


def _is_network_tool(tool_name: str) -> bool:
    """Return *True* if the tool name matches any network pattern."""
    for pattern in NETWORK_TOOL_PATTERNS:
        if pattern.search(tool_name):
            return True
    return False


def _check_url_restrictions(tool: dict) -> tuple[bool, list[str]]:
    """Check whether network-related parameters have URL/domain constraints.

    Returns (is_restricted, list_of_issues).
    """
    input_schema = tool.get("inputSchema")
    if not input_schema or not isinstance(input_schema, dict):
        return False, ["No inputSchema defined; URL parameters are unconstrained"]

    properties = input_schema.get("properties", {})
    if not isinstance(properties, dict):
        return False, ["inputSchema has no valid properties"]

    url_params_found: list[str] = []
    unrestricted_params: list[str] = []

    for param_name, param_def in properties.items():
        if not isinstance(param_def, dict):
            continue

        normalised = param_name.lower().strip()

        # Match against known URL parameter names
        is_url_param = normalised in _URL_PARAM_NAMES
        # Also check if the param format is "uri" or "url" (JSON Schema format)
        is_uri_format = param_def.get("format") in ("uri", "url", "iri")

        if not is_url_param and not is_uri_format:
            continue

        url_params_found.append(param_name)

        has_pattern = bool(param_def.get("pattern"))
        has_enum = bool(param_def.get("enum"))

        if not has_pattern and not has_enum:
            unrestricted_params.append(param_name)

    if not url_params_found:
        # Network tool without any recognisable URL parameter -- still risky
        # because the URL may be hardcoded or derived internally.
        return False, [
            "No recognisable URL/domain parameter found in schema; "
            "cannot verify network scope restriction"
        ]

    if unrestricted_params:
        issues = [
            f"Parameter '{p}' accepts arbitrary URLs without pattern or enum constraint"
            for p in unrestricted_params
        ]
        return False, issues

    return True, []


class NetworkAccessCheck(BaseCheck):
    """Check for unrestricted network access tools."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        network_tools_found = 0

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")

            if not _is_network_tool(tool_name):
                continue

            network_tools_found += 1

            is_restricted, issues = _check_url_restrictions(tool)

            if not is_restricted:
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
                            f"Network tool '{tool_name}' does not enforce "
                            f"URL or domain restrictions. "
                            f"{'; '.join(issues)}. This enables SSRF and "
                            f"data exfiltration to arbitrary endpoints."
                        ),
                        evidence="; ".join(issues),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and network_tools_found > 0:
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
                        f"All {network_tools_found} network tool(s) enforce "
                        f"URL or domain restrictions."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
