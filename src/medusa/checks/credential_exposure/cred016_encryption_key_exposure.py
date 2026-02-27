"""CRED016: Encryption Key Exposure.

Detects symmetric or asymmetric encryption keys in MCP server configuration. Exposed encryption
keys compromise the confidentiality of all data encrypted with those keys, including stored data
and communications.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class EncryptionKeyExposureCheck(BaseCheck):
    """Encryption Key Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement cred016 check logic
        return []
