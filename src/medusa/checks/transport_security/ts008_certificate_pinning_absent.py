"""TS008: Certificate Pinning Absent.

Detects MCP connections without certificate pinning for critical communication channels. Without
pinning, any certificate authority can issue a certificate for the server's domain, enabling
man-in-the-middle attacks by compromised or coerced CAs.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class CertificatePinningAbsentCheck(BaseCheck):
    """Certificate Pinning Absent."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ts008 check logic
        return []
