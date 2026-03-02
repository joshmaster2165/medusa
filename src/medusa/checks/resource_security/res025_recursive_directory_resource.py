"""RES-025: Recursive Directory Resource.

Detects resources that expose entire directories recursively. URIs
ending with /, /*, or /** and descriptions mentioning recursive access
suggest directory-level data exposure that can leak large amounts of
sensitive content.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# URI patterns indicating directory-level access
_DIR_URI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/\*\*\s*$"),  # ends with /**
    re.compile(r"/\*\s*$"),  # ends with /*
    re.compile(r"/\s*$"),  # ends with /
]

# Description keywords suggesting recursive access
_RECURSIVE_KEYWORDS: list[str] = [
    "recursive",
    "all files",
    "directory listing",
    "directory tree",
    "subdirectories",
]


class RecursiveDirectoryResourceCheck(BaseCheck):
    """Recursive Directory Resource."""

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
            description = resource.get("description", "") or ""
            reasons: list[str] = []

            # Check URI patterns
            for pattern in _DIR_URI_PATTERNS:
                if pattern.search(uri):
                    reasons.append(f"URI matches directory pattern: {pattern.pattern}")
                    break

            # Check description for recursive keywords
            desc_lower = description.lower()
            for keyword in _RECURSIVE_KEYWORDS:
                if keyword in desc_lower:
                    reasons.append(f"Description contains '{keyword}'")
                    break

            if reasons:
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
                            f"Resource '{name}' appears to expose a directory "
                            f"recursively. {'; '.join(reasons)}. URI: {uri}"
                        ),
                        evidence="; ".join(reasons),
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
                        f"No recursive directory exposure detected across "
                        f"{len(snapshot.resources)} resource(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
