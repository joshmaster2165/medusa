"""RES-004: Resource Injection via URI.

Checks resource URIs for injectable patterns (javascript:, data:,
protocol injection, shell metacharacters).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.injection import URL_INJECTION_PATTERNS
from medusa.utils.patterns.ssrf import DANGEROUS_SCHEMES

SHELL_METACHAR_PATTERN = re.compile(r"[;|&`$(){}<>\\]")
PROTOCOL_INJECTION_PATTERN = re.compile(r"^(javascript|data|vbscript|file):", re.IGNORECASE)


class ResourceInjectionViaUriCheck(BaseCheck):
    """Resource Injection via URI."""

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
            res_name = resource.get("name", "<unnamed>")
            uri = resource.get("uri", "")
            if not uri:
                continue

            issues: list[str] = []
            if SHELL_METACHAR_PATTERN.search(uri):
                issues.append("shell metacharacters in URI")
            if PROTOCOL_INJECTION_PATTERN.search(uri):
                issues.append("dangerous protocol scheme in URI")
            for pat in URL_INJECTION_PATTERNS:
                if pat.search(uri):
                    issues.append(f"injection pattern: {pat.pattern}")
            for scheme in DANGEROUS_SCHEMES:
                if uri.lower().startswith(f"{scheme}:"):
                    issues.append(f"dangerous scheme: {scheme}")

            if issues:
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
                            f"Resource '{res_name}' URI '{uri[:80]}' contains "
                            f"injectable patterns: {issues[0]}"
                        ),
                        evidence=f"uri={uri!r}, issues={issues[:3]}",
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
                    status_extended="No URI injection patterns detected in resources.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
