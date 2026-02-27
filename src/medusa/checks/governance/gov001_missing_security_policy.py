"""GOV001: Missing Security Policy.

Detects MCP server deployments that lack a documented security policy defining security
requirements, controls, and responsibilities for the MCP server and its integrations. A security
policy establishes the baseline for secure operation and communicates expectations to all
stakeholders.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import POLICY_CONFIG_KEYS


def _walk_config_for_keys(config: Any, keys: set[str], _depth: int = 0) -> bool:
    """Recursively walk a config dict looking for any of the given keys."""
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


def _gov_check(
    snapshot: ServerSnapshot,
    meta: CheckMetadata,
    config_keys: set[str],
    missing_msg: str,
    present_msg: str,
) -> list[Finding]:
    """Governance config-key check: FAIL if absent, PASS if present."""
    found = _walk_config_for_keys(snapshot.config_raw or {}, config_keys)
    status = Status.PASS if found else Status.FAIL
    return [
        Finding(
            check_id=meta.check_id,
            check_title=meta.title,
            status=status,
            severity=meta.severity,
            server_name=snapshot.server_name,
            server_transport=snapshot.transport_type,
            resource_type="server",
            resource_name=snapshot.server_name,
            status_extended=(
                present_msg.format(server=snapshot.server_name)
                if found
                else missing_msg.format(server=snapshot.server_name)
            ),
            evidence=f"config_raw present: {bool(snapshot.config_raw)}",
            remediation=meta.remediation,
            owasp_mcp=meta.owasp_mcp,
        )
    ]


class MissingSecurityPolicyCheck(BaseCheck):
    """Missing Security Policy."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _gov_check(
            snapshot,
            meta,
            config_keys=POLICY_CONFIG_KEYS,
            missing_msg=(
                "Server '{server}' has no security policy configuration. "
                "Document security requirements and controls."
            ),
            present_msg="Server '{server}' has a security policy configured.",
        )
