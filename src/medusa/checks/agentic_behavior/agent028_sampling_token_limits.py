"""AGENT028: Sampling Without Token/Budget Limits.

Detects when a server enables the MCP sampling capability without configuring
token budget or invocation limits. Unbounded sampling can exhaust API credits
and enable runaway agentic loops.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_LIMIT_KEYS: set[str] = {
    "maxTokens",
    "max_tokens",
    "budget",
    "limit",
    "maxMessages",
    "max_messages",
}


class SamplingTokenLimitsCheck(BaseCheck):
    """Detect sampling capability without token or budget limits."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        sampling_cap = snapshot.capabilities.get("sampling")

        if sampling_cap is None:
            # Not applicable -- sampling not enabled
            return findings

        # Check if the capability has any budget/limit fields
        if isinstance(sampling_cap, dict):
            has_limits = bool(set(sampling_cap.keys()) & _LIMIT_KEYS)
        else:
            has_limits = False

        if not has_limits:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        "Server enables sampling capability without token "
                        "budget limits. The sampling capability object does "
                        "not contain maxTokens or budget fields, allowing "
                        "unbounded LLM invocations that could exhaust API "
                        "credits."
                    ),
                    evidence=f"sampling_capability={sampling_cap}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
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
                    status_extended=("Sampling capability has token limits configured."),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
