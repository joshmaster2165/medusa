"""RES-008: Resource Symlink Following.

Checks file:// resources for symlink following risk. Fails when
file-based resources exist and no symlink protection config is found.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

SYMLINK_PROTECTION_KEYS: set[str] = {
    "follow_symlinks",
    "no_follow_symlinks",
    "symlink_protection",
    "resolve_symlinks",
    "chroot",
    "sandbox",
    "jail",
    "restricted_path",
}


class ResourceSymlinkRiskCheck(BaseCheck):
    """Resource Symlink Following."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.resources:
            return findings

        file_resources = [r for r in snapshot.resources if r.get("uri", "").startswith("file://")]

        if not file_resources:
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
                    status_extended="No file:// resources detected — symlink risk not applicable.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        has_protection = _walk_config_for_keys(snapshot.config_raw, SYMLINK_PROTECTION_KEYS)

        if not has_protection:
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
                            f"File resource '{res_name}' ({uri}) has no symlink "
                            f"protection or sandbox config — symlink following may expose "
                            f"arbitrary files."
                        ),
                        evidence=f"uri={uri!r}; no symlink protection config.",
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
                    status_extended="Symlink protection configuration detected.",
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
