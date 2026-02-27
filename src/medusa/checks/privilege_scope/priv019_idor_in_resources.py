"""PRIV-019: IDOR in Resource Access.

Detects resources with sequential/guessable numeric IDs in their URIs,
indicating potential Insecure Direct Object Reference vulnerabilities.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Pattern matching URIs with sequential numeric IDs (e.g., /users/123, /items/42)
_SEQUENTIAL_ID_PATTERN = re.compile(r"/\d{1,10}(/|$)")
# Pattern for obviously guessable IDs in URI templates
_GUESSABLE_TEMPLATE = re.compile(r"\{(id|user_id|item_id|record_id|doc_id)\}", re.IGNORECASE)


class IdorInResourcesCheck(BaseCheck):
    """Detect resources with sequential or guessable IDs indicating IDOR risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.resources:
            return findings

        for resource in snapshot.resources:
            uri = resource.get("uri", "")
            res_name = resource.get("name", uri)

            has_sequential = bool(_SEQUENTIAL_ID_PATTERN.search(uri))
            has_guessable = bool(_GUESSABLE_TEMPLATE.search(uri))

            if not (has_sequential or has_guessable):
                continue

            reason = "sequential numeric ID" if has_sequential else "guessable ID template"
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="resource",
                    resource_name=res_name,
                    status_extended=(
                        f"Resource '{res_name}' (URI: {uri}) has a {reason}, "
                        f"enabling IDOR access to other users' resources."
                    ),
                    evidence=f"URI: {uri} ({reason})",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        if not findings and snapshot.resources:
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
                    status_extended="No sequential or guessable resource IDs detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
