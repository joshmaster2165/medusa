"""RES-006: Resource Race Condition (TOCTOU).

Checks for file:// resources that could have TOCTOU issues. Flags
file-backed resources without atomic access or locking config.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

ATOMIC_ACCESS_KEYS: set[str] = {
    "atomic",
    "locking",
    "file_lock",
    "mutex",
    "exclusive_access",
    "transactional",
    "toctou_protection",
}


class ResourceRaceConditionCheck(BaseCheck):
    """Resource Race Condition."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.resources:
            return findings

        has_locking = _walk_config_for_keys(snapshot.config_raw, ATOMIC_ACCESS_KEYS)

        file_resources = [r for r in snapshot.resources if r.get("uri", "").startswith("file://")]

        if file_resources and not has_locking:
            for resource in file_resources:
                res_name = resource.get("name", "<unnamed>")
                uri = resource.get("uri", "")
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
                            f"File resource '{res_name}' ({uri}) may be vulnerable to "
                            f"TOCTOU race conditions without atomic access/locking config."
                        ),
                        evidence=f"uri={uri!r}; no locking config found.",
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
                    status_extended="No unprotected TOCTOU-vulnerable file resources detected.",
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
