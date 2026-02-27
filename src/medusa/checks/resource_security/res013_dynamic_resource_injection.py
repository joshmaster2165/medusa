"""RES-013: Dynamic Resource Injection.

Checks if resources can be dynamically added by checking for dynamic
resource registration tools/config without validation controls.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.authentication import AUTH_CONFIG_KEYS

DYNAMIC_RESOURCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(register|add|create|inject)[-_]?(resource|endpoint|uri)", re.IGNORECASE),
    re.compile(r"dynamic[-_]?(resource|content|endpoint)", re.IGNORECASE),
    re.compile(r"(resource|content)[-_]?(register|add|inject|dynamic)", re.IGNORECASE),
]


class DynamicResourceInjectionCheck(BaseCheck):
    """Dynamic Resource Injection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.resources:
            return findings

        has_auth = _walk_config_for_keys(snapshot.config_raw, AUTH_CONFIG_KEYS)

        dynamic_tools: list[str] = []
        for tool in snapshot.tools:
            combined = f"{tool.get('name', '')} {tool.get('description', '')}"
            if any(p.search(combined) for p in DYNAMIC_RESOURCE_PATTERNS):
                dynamic_tools.append(tool.get("name", "<unnamed>"))

        if dynamic_tools and not has_auth:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Dynamic resource injection tools detected "
                        f"({', '.join(dynamic_tools[:5])}) without auth/validation config."
                    ),
                    evidence=f"dynamic_tools={dynamic_tools[:5]}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
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
                    status_extended="No uncontrolled dynamic resource injection detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings


def _walk_config_for_keys(config: Any, keys: set[str], _depth: int = 0) -> bool:
    if _depth > 10:
        return False
    if isinstance(config, dict):
        for key in config:
            if isinstance(key, str) and key.lower() in keys:
                return True
            if _walk_config_for_keys(config[key], keys, _depth + 1):
                return True
    elif isinstance(config, list):
        for item in config:
            if _walk_config_for_keys(item, keys, _depth + 1):
                return True
    return False
