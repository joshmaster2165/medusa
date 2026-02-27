"""PRIV-022: Missing Least Privilege.

Checks if a server with only benign tools (no filesystem/shell/network tools)
declares broad capabilities, indicating over-permissioned deployment.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.filesystem import (
    ADMIN_TOOL_PATTERNS,
    DESTRUCTIVE_TOOL_PATTERNS,
    FS_TOOL_PATTERNS,
    SHELL_TOOL_NAMES,
)
from medusa.utils.patterns.network import NETWORK_TOOL_PATTERNS

_BROAD_CAPABILITY_KEYS = {
    "all",
    "full_access",
    "unrestricted",
    "superuser",
    "root",
    "admin",
    "wildcard",
    "*",
    "any",
    "everything",
}


def _tool_has_high_privilege(tool_name: str) -> bool:
    name_lower = tool_name.lower()
    if name_lower in SHELL_TOOL_NAMES:
        return True
    for pat in (
        FS_TOOL_PATTERNS + DESTRUCTIVE_TOOL_PATTERNS + ADMIN_TOOL_PATTERNS + NETWORK_TOOL_PATTERNS
    ):
        if pat.search(tool_name):
            return True
    return False


class MissingLeastPrivilegeCheck(BaseCheck):
    """Detect servers declaring broad capabilities beyond what their tools require."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Check capabilities for broad scope declarations
        cap_str = str(snapshot.capabilities).lower()
        broad_caps = [k for k in _BROAD_CAPABILITY_KEYS if k in cap_str]

        # Count tools that actually require elevated privilege
        high_priv_tools = [
            t["name"] for t in snapshot.tools if _tool_has_high_privilege(t.get("name", ""))
        ]

        # Flag if broad capabilities declared but no high-privilege tools justify them
        if broad_caps and not high_priv_tools:
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
                        f"Server declares broad capabilities ({broad_caps}) but none "
                        f"of the {len(snapshot.tools)} tool(s) require elevated privileges, "
                        f"violating least privilege."
                    ),
                    evidence=f"Broad capability keys: {broad_caps}",
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
                    status_extended="No least-privilege violations detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
