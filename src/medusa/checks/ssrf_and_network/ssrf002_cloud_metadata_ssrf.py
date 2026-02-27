"""SSRF002: Cloud Metadata SSRF.

Detects MCP server tools that can access cloud instance metadata endpoints, particularly the AWS
metadata service at 169.254.169.254 and equivalent endpoints for GCP, Azure, and other cloud
providers. These endpoints expose temporary credentials, instance identity documents, and
configuration data.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class CloudMetadataSsrfCheck(BaseCheck):
    """Cloud Metadata SSRF."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf002 check logic
        return []
