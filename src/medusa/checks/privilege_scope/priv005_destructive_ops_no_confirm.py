"""PRIV-005: Destructive Operations Without Confirmation.

Detects tools whose names match destructive patterns (delete, drop, purge, etc.)
but lack a confirmation parameter in their input schema.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.filesystem import DESTRUCTIVE_TOOL_PATTERNS

_CONFIRM_PARAM_NAMES = {
    "confirm",
    "confirmation",
    "confirmed",
    "approve",
    "approved",
    "consent",
    "destructive_hint",
    "force",
}


class DestructiveOpsNoConfirmCheck(BaseCheck):
    """Detect destructive tools lacking explicit confirmation parameters."""

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

            # Check if tool name matches destructive patterns
            is_destructive = any(pat.search(tool_name) for pat in DESTRUCTIVE_TOOL_PATTERNS)
            if not is_destructive:
                continue

            input_schema = tool.get("inputSchema") or {}
            properties = (
                input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
            )
            annotations = tool.get("annotations") or {}

            # Check for confirmation param or destructiveHint annotation
            has_confirm_param = any(p.lower() in _CONFIRM_PARAM_NAMES for p in properties)
            has_destructive_hint = bool(annotations.get("destructiveHint"))

            if has_confirm_param or has_destructive_hint:
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
                    resource_name=tool_name,
                    status_extended=(
                        f"Destructive tool '{tool_name}' has no confirmation "
                        f"parameter or destructiveHint annotation. It can be "
                        f"triggered without explicit user consent."
                    ),
                    evidence=f"No confirm param found among: {list(properties.keys())}",
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
                    status_extended="All destructive tools have confirmation mechanisms.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
