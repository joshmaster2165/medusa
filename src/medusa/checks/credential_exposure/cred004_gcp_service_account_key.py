"""CRED004: GCP Service Account Key Exposure.

Detects Google Cloud Platform service account JSON key files in MCP server configuration or
environment. GCP service account keys contain private keys that grant full access to the
associated cloud project resources and APIs.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class GcpServiceAccountKeyCheck(BaseCheck):
    """GCP Service Account Key Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement cred004 check logic
        return []
