"""SSRF-009: IP Address Representation Bypass.

Detects tools with URL/host params that lack normalization hints (pattern
constraints enforcing dotted-decimal notation), leaving them vulnerable to
octal, hex, decimal, or IPv6-mapped IP encoding bypasses.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.ssrf import URL_PARAM_NAMES

# Pattern matching numeric-encoded IP representations in descriptions/defaults
_ENCODED_IP_PATTERNS = [
    re.compile(r"0x[0-9a-f]{8}", re.IGNORECASE),  # hex: 0x7f000001
    re.compile(r"0[0-7]{3}\.[0-7]{3}\.[0-7]{3}\.[0-7]{3}"),  # octal: 0177.0.0.1
    re.compile(r"\b\d{8,10}\b"),  # decimal: 2130706433
    re.compile(r"::ffff:", re.IGNORECASE),  # IPv6-mapped IPv4
]


class IpAddressBypassCheck(BaseCheck):
    """Detect tools vulnerable to IP address encoding bypass attacks."""

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
            tool_name = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema") or {}
            properties = (
                input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
            )
            description = tool.get("description", "") or ""
            searchable = f"{description} {str(input_schema)}"

            url_params = [p for p in properties if p.lower() in URL_PARAM_NAMES]
            if not url_params:
                continue

            # Check for encoded IP patterns in description/schema
            encoded_hits = [p.pattern for p in _ENCODED_IP_PATTERNS if p.search(searchable)]

            # Or URL params with no IP-normalizing pattern constraint
            unconstrained = [
                p
                for p in url_params
                if isinstance(properties.get(p), dict)
                and not properties[p].get("pattern")
                and not properties[p].get("enum")
            ]

            if not (encoded_hits or unconstrained):
                continue

            evidence_parts = []
            if encoded_hits:
                evidence_parts.append(f"encoded IP patterns: {encoded_hits}")
            if unconstrained:
                evidence_parts.append(f"unconstrained URL params: {unconstrained}")

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
                        f"Tool '{tool_name}' may be vulnerable to IP address "
                        f"encoding bypass. {'; '.join(evidence_parts)}."
                    ),
                    evidence="; ".join(evidence_parts),
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
                    status_extended="No IP address encoding bypass risk detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
