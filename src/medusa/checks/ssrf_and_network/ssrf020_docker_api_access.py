"""SSRF-020: Docker API Access.

Detects tool descriptions or schemas referencing Docker daemon API access
patterns (/var/run/docker.sock, Docker TCP ports 2375/2376, docker commands).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_DOCKER_PATTERNS = [
    re.compile(r"/var/run/docker\.sock", re.IGNORECASE),
    re.compile(r"tcp://[^:]+:237[56]\b", re.IGNORECASE),
    re.compile(r"\bdocker\.sock\b", re.IGNORECASE),
    re.compile(r"unix:///var/run/docker", re.IGNORECASE),
    re.compile(r"DOCKER_HOST", re.IGNORECASE),
    re.compile(r"\bdocker (run|exec|container|ps|pull|push)\b", re.IGNORECASE),
]


class DockerApiAccessCheck(BaseCheck):
    """Detect tools with Docker API or daemon socket access patterns."""

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
            hits = [pat.pattern for pat in _DOCKER_PATTERNS if pat.search(searchable)]
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
                        f"Tool '{tool_name}' contains Docker API access patterns, "
                        f"enabling container escape and host filesystem access."
                    ),
                    evidence=f"Docker patterns found: {hits[:3]}",
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
                    status_extended="No Docker API access patterns detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
