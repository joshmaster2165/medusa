"""PRIV-020: Missing Resource Authorization.

Checks whether resources expose sensitive content (SSH keys, secrets, PII) in
their descriptions without any authorization annotation, indicating unprotected access.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SENSITIVE_RESOURCE_PATTERN = re.compile(
    r"\b(private.key|ssh.key|secret|credential|password|token|"
    r"api.key|access.key|sensitive|confidential|personal|pii)\b",
    re.IGNORECASE,
)


class MissingResourceAuthorizationCheck(BaseCheck):
    """Detect resources with sensitive content lacking authorization hints."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.resources:
            return findings

        config_str = str(snapshot.config_raw).lower() if snapshot.config_raw else ""
        has_authz = any(
            k in config_str for k in {"authorization", "authz", "rbac", "acl", "access_control"}
        )

        for resource in snapshot.resources:
            uri = resource.get("uri", "")
            res_name = resource.get("name", uri)
            description = resource.get("description", "") or ""
            searchable = f"{uri} {res_name} {description}"

            is_sensitive = bool(_SENSITIVE_RESOURCE_PATTERN.search(searchable))
            if not is_sensitive:
                continue

            if has_authz:
                continue

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
                        f"Sensitive resource '{res_name}' (URI: {uri}) appears to "
                        f"lack authorization controls, allowing unrestricted access."
                    ),
                    evidence=f"Sensitive resource without authorization config: {uri}",
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
                    status_extended="All sensitive resources have authorization configuration.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
