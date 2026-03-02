"""RES-021: Wildcard Resource URI Patterns.

Detects resource URIs containing glob or wildcard patterns that expose
overly broad access to server-side data. Wildcards like *, **, ?, {}, and
[] allow clients to match and retrieve large sets of resources without
explicit enumeration.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Patterns that indicate wildcard / glob usage in a URI
_WILDCARD_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\*\*"),  # recursive glob
    re.compile(r"(?<!\*)\*(?!\*)"),  # single glob star (not **)
    re.compile(r"\?"),  # single-char wildcard
    re.compile(r"\{[^}]+\}"),  # brace expansion {a,b}
    re.compile(r"\[[^\]]+\]"),  # character class [abc]
    re.compile(r"\(\.\*\)"),  # regex wildcard (.*)
]


class WildcardResourceUriCheck(BaseCheck):
    """Wildcard Resource URI Patterns."""

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
            name = resource.get("name", "<unnamed>")
            matched: list[str] = []

            for pattern in _WILDCARD_PATTERNS:
                match = pattern.search(uri)
                if match:
                    matched.append(match.group())

            if matched:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="resource",
                        resource_name=name,
                        status_extended=(
                            f"Resource '{name}' URI contains wildcard patterns: "
                            f"{', '.join(matched)}. URI: {uri}"
                        ),
                        evidence=f"Wildcard patterns in URI: {', '.join(matched)}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings:
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
                        f"No wildcard URI patterns detected across "
                        f"{len(snapshot.resources)} resource(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
