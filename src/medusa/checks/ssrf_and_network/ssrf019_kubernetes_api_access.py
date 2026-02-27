"""SSRF-019: Kubernetes API Access.

Detects tool descriptions or schemas referencing Kubernetes API patterns
(kubernetes.default.svc, /apis/, serviceaccount tokens, kubectl commands).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_K8S_PATTERNS = [
    re.compile(r"kubernetes\.default\.svc", re.IGNORECASE),
    re.compile(r"/var/run/secrets/kubernetes\.io/", re.IGNORECASE),
    re.compile(r"\bkubectl\b", re.IGNORECASE),
    re.compile(r"\bkubeconfig\b", re.IGNORECASE),
    re.compile(r"https?://[^/]*:\d+/apis?/", re.IGNORECASE),
    re.compile(r"\bkube-apiserver\b", re.IGNORECASE),
    re.compile(r"\.svc\.cluster\.local", re.IGNORECASE),
]


class KubernetesApiAccessCheck(BaseCheck):
    """Detect tools with Kubernetes API access patterns."""

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
            searchable = f"{tool.get('description', '')} {str(tool.get('inputSchema', {}))}"
            hits = [pat.pattern for pat in _K8S_PATTERNS if pat.search(searchable)]
            if not hits:
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
                        f"Tool '{tool_name}' contains Kubernetes API access patterns, "
                        f"enabling cluster-wide enumeration and resource manipulation."
                    ),
                    evidence=f"K8s patterns found: {hits[:3]}",
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
                    status_extended="No Kubernetes API access patterns detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
