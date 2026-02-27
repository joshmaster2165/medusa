"""SHADOW-001: Generic or Duplicate-Prone Server Name.

Detects MCP servers using generic, short, or commonly duplicated names
that increase the risk of server shadowing attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import GENERIC_SERVER_NAMES

_MIN_NAME_LENGTH = 3


class GenericServerNameCheck(BaseCheck):
    """Check for generic or overly short server names."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        name_lower = snapshot.server_name.lower().strip()
        issues: list[str] = []

        if name_lower in GENERIC_SERVER_NAMES:
            issues.append(
                f"Server name '{snapshot.server_name}' is a commonly used "
                f"generic name that is easily impersonated."
            )

        if len(name_lower) < _MIN_NAME_LENGTH:
            issues.append(
                f"Server name '{snapshot.server_name}' is too short "
                f"({len(name_lower)} chars, minimum is {_MIN_NAME_LENGTH})."
            )

        if issues:
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
                        f"Server '{snapshot.server_name}' has a generic or "
                        f"overly short name: {'; '.join(issues)}"
                    ),
                    evidence=f"server_name={snapshot.server_name}",
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
                    status_extended=(
                        f"Server '{snapshot.server_name}' has a unique, descriptive name."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
