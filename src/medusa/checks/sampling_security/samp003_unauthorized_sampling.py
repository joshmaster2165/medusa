"""SAMP003: Unauthorized Sampling Requests.

Detects MCP server implementations that issue sampling requests to the LLM client without
explicit user consent or authorization. Sampling allows the server to request LLM completions,
and without proper consent mechanisms, servers can silently invoke the LLM to process attacker-
controlled prompts.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class UnauthorizedSamplingCheck(BaseCheck):
    """Unauthorized Sampling Requests."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement samp003 check logic
        return []
