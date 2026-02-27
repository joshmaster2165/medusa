"""SSRF001: Private IP Address Access.

Detects MCP server tools that allow requests to private IP address ranges (10.0.0.0/8,
172.16.0.0/12, 192.168.0.0/16) without restriction. Tools accepting user-controlled URLs or
hostnames can be abused to access internal network resources that should not be reachable from
the MCP server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class PrivateIpAccessCheck(BaseCheck):
    """Private IP Address Access."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf001 check logic
        return []
