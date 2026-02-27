"""SESS009: Session Data Exposure.

Detects MCP server implementations that store sensitive data directly in session objects or
transmit session contents to the client. Session data may include tool invocation history, user
credentials, resource URIs, or intermediate computation results that should not be exposed to
the LLM client or stored in client-accessible session storage.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SessionDataExposureCheck(BaseCheck):
    """Session Data Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sess009 check logic
        return []
