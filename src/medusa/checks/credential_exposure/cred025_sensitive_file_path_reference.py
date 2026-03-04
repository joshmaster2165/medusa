"""CRED025: Sensitive File Path References in Tool Metadata.

Detects tools whose descriptions or parameter default values reference
sensitive file paths such as /etc/passwd, .env, .ssh/, .aws/credentials,
or other configuration files commonly targeted for credential harvesting.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SENSITIVE_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"/etc/passwd\b"), "/etc/passwd"),
    (re.compile(r"/etc/shadow\b"), "/etc/shadow"),
    (re.compile(r"/etc/hosts\b"), "/etc/hosts"),
    (re.compile(r"\.env\b"), ".env"),
    (re.compile(r"\.aws/credentials\b"), ".aws/credentials"),
    (re.compile(r"\.ssh/"), ".ssh/"),
    (re.compile(r"\.netrc\b"), ".netrc"),
    (re.compile(r"\.npmrc\b"), ".npmrc"),
    (re.compile(r"\.pypirc\b"), ".pypirc"),
    (re.compile(r"/proc/self/"), "/proc/self/"),
    (re.compile(r"secrets\.ya?ml\b"), "secrets.yaml"),
    (re.compile(r"\.git/config\b"), ".git/config"),
    (re.compile(r"docker-compose.*\.ya?ml\b"), "docker-compose.yml"),
    (re.compile(r"\.kube/config\b"), ".kube/config"),
    (re.compile(r"\bid_rsa\b"), "id_rsa"),
    (re.compile(r"\.pem\b"), ".pem"),
    (re.compile(r"credentials\.json\b"), "credentials.json"),
    (re.compile(r"service[-_]?account\.json\b"), "service_account.json"),
    (re.compile(r"\.htpasswd\b"), ".htpasswd"),
    (re.compile(r"wp-config\.php\b"), "wp-config.php"),
]


class SensitiveFilePathReferenceCheck(BaseCheck):
    """Sensitive File Path References in Tool Metadata."""

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
            tool_name: str = tool.get("name", "<unnamed>")
            # Collect all text: description + parameter descriptions + defaults
            parts: list[str] = [tool.get("description", "") or ""]
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            for param_def in properties.values():
                if not isinstance(param_def, dict):
                    continue
                parts.append(param_def.get("description", "") or "")
                default = param_def.get("default")
                if isinstance(default, str):
                    parts.append(default)
            all_text = " ".join(parts)

            if not all_text.strip():
                continue

            matched_paths: list[str] = []
            for pattern, label in _SENSITIVE_PATH_PATTERNS:
                if pattern.search(all_text):
                    matched_paths.append(label)

            if matched_paths:
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
                            f"Tool '{tool_name}' references sensitive "
                            f"file paths: {', '.join(matched_paths[:5])}. "
                            f"This may enable credential harvesting."
                        ),
                        evidence=(f"sensitive_paths={matched_paths}"),
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
                    status_extended=(
                        f"No sensitive file path references detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
