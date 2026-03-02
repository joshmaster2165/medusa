"""RES-024: Resource URI Template Injection.

Detects resource URI templates with parameters that could be manipulated
for path traversal or command execution. URI templates like file:///{path}
allow arbitrary path access if the path parameter is not validated.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Severity, Status

# Regex to find template parameters like {param}, {path}, etc.
_TEMPLATE_PARAM_RE = re.compile(r"\{([^}]+)\}")

# URI schemes that are dangerous when combined with template parameters
_SENSITIVE_SCHEMES: set[str] = {
    "file://",
    "exec://",
    "cmd://",
    "data://",
    "javascript:",
}


class UriTemplateInjectionCheck(BaseCheck):
    """Resource URI Template Injection."""

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

            params = _TEMPLATE_PARAM_RE.findall(uri)
            if not params:
                continue

            uri_lower = uri.lower()
            has_sensitive_scheme = any(
                uri_lower.startswith(scheme) for scheme in _SENSITIVE_SCHEMES
            )

            if has_sensitive_scheme:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=Severity.CRITICAL,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="resource",
                        resource_name=name,
                        status_extended=(
                            f"Resource '{name}' uses template parameters "
                            f"({', '.join(params)}) with a sensitive URI scheme. "
                            f"This may allow arbitrary path access or command "
                            f"execution. URI: {uri}"
                        ),
                        evidence=(
                            f"Template params: {', '.join(params)}; "
                            f"Sensitive scheme detected in URI: {uri}"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=Severity.MEDIUM,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="resource",
                        resource_name=name,
                        status_extended=(
                            f"Resource '{name}' uses template parameters "
                            f"({', '.join(params)}) in its URI. Ensure "
                            f"parameters are validated server-side. URI: {uri}"
                        ),
                        evidence=f"Template params: {', '.join(params)}; URI: {uri}",
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
                        f"No URI template injection risks detected across "
                        f"{len(snapshot.resources)} resource(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
