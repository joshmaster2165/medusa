"""AUTH018: Missing Mutual TLS.

Detects MCP servers that do not require client certificate authentication (mutual TLS). Without
mTLS, the server cannot cryptographically verify the identity of connecting clients, relying
solely on application-layer credentials that may be stolen or forged.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingMutualTlsCheck(BaseCheck):
    """Missing Mutual TLS."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth018 check logic
        return []
