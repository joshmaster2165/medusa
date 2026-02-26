"""DP-002: Detect sensitive file paths and secrets in MCP resource URIs.

Scans every resource's ``uri`` and ``uriTemplate`` fields for references to
sensitive files (private keys, credential stores, SSH directories) and for
hardcoded secrets (API keys, tokens, passwords).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import SECRET_PATTERNS, SENSITIVE_PATH_PATTERNS


class SensitiveResourceUrisCheck(BaseCheck):
    """Check for sensitive file paths and secrets in resource URIs."""

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
            res_name: str = resource.get("name", "<unnamed>")
            uri: str = resource.get("uri", "")
            uri_template: str = resource.get("uriTemplate", "")

            # Collect URI surfaces to scan
            surfaces: list[tuple[str, str]] = []
            if uri:
                surfaces.append(("uri", uri))
            if uri_template:
                surfaces.append(("uriTemplate", uri_template))

            for surface_label, text in surfaces:
                issues: list[str] = []

                # Check for sensitive file paths
                for pattern in SENSITIVE_PATH_PATTERNS:
                    match = pattern.search(text)
                    if match:
                        issues.append(
                            f"Sensitive path pattern: '{match.group()}'"
                        )

                # Check for hardcoded secrets
                for secret_name, pattern in SECRET_PATTERNS:
                    match = pattern.search(text)
                    if match:
                        issues.append(f"Hardcoded secret ({secret_name})")

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
                                f"Resource '{res_name}' {surface_label} references "
                                f"sensitive content: {'; '.join(issues)}"
                            ),
                            evidence="; ".join(issues),
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # Emit PASS if resources were checked but none had issues
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
                    status_extended=(
                        f"No sensitive paths or secrets detected across "
                        f"{len(snapshot.resources)} resource(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
