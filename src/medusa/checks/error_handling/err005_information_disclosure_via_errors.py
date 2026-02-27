"""ERR005: Information Disclosure via Errors.

Detects MCP server error responses that disclose system-level information such as operating
system details, hostname, IP addresses, user account names, installed software versions, or
runtime environment configuration.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class InformationDisclosureViaErrorsCheck(BaseCheck):
    """Information Disclosure via Errors."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err005 check logic
        return []
