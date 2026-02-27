"""CRED023: HashiCorp Vault Token Exposure.

Detects HashiCorp Vault root tokens or service tokens in MCP server configuration. Vault tokens
provide access to the secrets management infrastructure itself, potentially exposing all secrets
stored in the vault.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class VaultTokenExposureCheck(BaseCheck):
    """HashiCorp Vault Token Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement cred023 check logic
        return []
