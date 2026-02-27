"""TS009: Self-Signed Certificate Usage.

Detects MCP servers using self-signed TLS certificates. Self-signed certificates cannot be
verified against a trusted certificate authority chain, requiring clients to disable certificate
validation and making them vulnerable to man-in-the-middle attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SelfSignedCertificateCheck(BaseCheck):
    """Self-Signed Certificate Usage."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ts009 check logic
        return []
