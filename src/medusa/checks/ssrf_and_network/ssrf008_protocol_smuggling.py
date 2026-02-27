"""SSRF-008: Protocol Smuggling Risk.

Detects tools with URL/host params that include no scheme validation, allowing
dangerous alternative protocol schemes (gopher://, dict://, ftp://, ldap://)
to be smuggled through HTTP fetch tools.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.ssrf import DANGEROUS_SCHEMES, URL_PARAM_NAMES

# Param names that could carry raw protocol/scheme data
_SMUGGLE_PARAM_NAMES = {"scheme", "protocol", "method", "raw_url", "request_uri"}


class ProtocolSmugglingCheck(BaseCheck):
    """Detect tools where parameter names suggest raw protocol/scheme input."""

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

            # Check for scheme/protocol param names that allow arbitrary protocols
            smuggle_params = [p for p in properties if p.lower() in _SMUGGLE_PARAM_NAMES]

            # Also check if URL params exist with no scheme constraint
            url_params = [p for p in properties if p.lower() in URL_PARAM_NAMES]
            unconstrained_url = [
                p
                for p in url_params
                if isinstance(properties.get(p), dict)
                and not properties[p].get("pattern")
                and not properties[p].get("enum")
            ]

            # Check description for dangerous scheme mentions
            desc_lower = description.lower()
            scheme_mentions = [s for s in DANGEROUS_SCHEMES if s + "://" in desc_lower]

            if not (smuggle_params or scheme_mentions or unconstrained_url):
                continue

            evidence_parts = []
            if smuggle_params:
                evidence_parts.append(f"protocol/scheme params: {smuggle_params}")
            if scheme_mentions:
                evidence_parts.append(f"dangerous schemes in description: {scheme_mentions}")
            if unconstrained_url:
                evidence_parts.append(f"unconstrained URL params: {unconstrained_url}")

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
                        f"Tool '{tool_name}' may allow protocol smuggling. "
                        f"{'; '.join(evidence_parts)}."
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
                    status_extended="No protocol smuggling indicators detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
