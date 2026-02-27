"""CRED005: Azure Credential Exposure.

Detects Azure client secrets, certificate thumbprints, or managed identity credentials in MCP
server configuration. Azure credentials in configuration files grant access to Azure Active
Directory, storage accounts, databases, and other cloud services.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class AzureCredentialsCheck(BaseCheck):
    """Azure Credential Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement cred005 check logic
        return []
