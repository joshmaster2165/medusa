"""TS018: Proxy Without TLS.

Detects MCP server proxy configurations that do not use TLS encryption. Proxies without TLS
decrypt and re-encrypt traffic, creating a plaintext exposure point. Unencrypted proxy
connections expose all traffic to interception at the proxy hop.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ProxyWithoutTlsCheck(BaseCheck):
    """Proxy Without TLS."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ts018 check logic
        return []
