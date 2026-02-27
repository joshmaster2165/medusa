"""HARD015: Missing Network Segmentation.

Detects MCP servers deployed without network segmentation between client-facing interfaces and
backend services. Without segmentation, a compromised MCP server has direct network access to
databases, internal APIs, and other sensitive backend services.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_NETWORK_SEG_KEYS = {
    "network_policy",
    "firewall",
    "vpc",
    "vnet",
    "network_segmentation",
    "security_group",
    "egress_filter",
    "ingress_filter",
    "network_acl",
}


class MissingNetworkSegmentationCheck(BaseCheck):
    """Missing Network Segmentation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=_NETWORK_SEG_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' has no network segmentation configuration. "
                "A compromised server may have direct access to backend services."
            ),
            present_msg=("Server '{server}' has network segmentation or policy configuration."),
            fail_on_present=False,
        )
