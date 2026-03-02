"""SM016: High-Entropy Default Values.

Detects tool parameter default values that have high Shannon entropy,
suggesting hardcoded secrets such as API keys, tokens, or passwords
embedded directly in the tool's JSON Schema definition.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import is_likely_secret


class HighEntropyDefaultsCheck(BaseCheck):
    """High-Entropy Default Values."""

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
            tool_name = tool.get("name", "unknown")
            schema = tool.get("inputSchema") or {}
            properties = schema.get("properties") or {}

            self._walk_properties(
                properties, tool_name, meta, snapshot, findings,
            )

        if not findings:
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended="No high-entropy default values detected in tool parameters.",
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))
        return findings

    def _walk_properties(
        self,
        properties: dict[str, Any],
        tool_name: str,
        meta: CheckMetadata,
        snapshot: ServerSnapshot,
        findings: list[Finding],
        prefix: str = "",
    ) -> None:
        """Recursively walk JSON Schema properties looking for high-entropy defaults."""
        for param_name, param_def in properties.items():
            if not isinstance(param_def, dict):
                continue

            full_name = f"{prefix}{param_name}" if not prefix else f"{prefix}.{param_name}"
            default = param_def.get("default")

            if isinstance(default, str) and len(default) >= 8:
                is_secret, confidence = is_likely_secret(param_name, default)
                if is_secret and confidence >= 0.6:
                    # Mask the secret in evidence
                    masked = default[:4] + "*" * (len(default) - 4)
                    findings.append(Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=(
                            f"Tool '{tool_name}' parameter '{full_name}' has a high-entropy "
                            f"default value (confidence: {confidence:.0%}) that may be a "
                            f"hardcoded secret."
                        ),
                        evidence=f"Parameter: {full_name}, Default: {masked}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    ))

            # Recurse into nested object properties
            nested_props = param_def.get("properties")
            if isinstance(nested_props, dict):
                self._walk_properties(
                    nested_props, tool_name, meta, snapshot, findings, full_name,
                )
