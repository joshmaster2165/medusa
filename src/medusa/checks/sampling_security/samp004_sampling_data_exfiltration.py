"""SAMP004: Data Exfiltration via Sampling.

Detects MCP server configurations where sampling requests can be used as a channel to exfiltrate
sensitive data from the LLM's context. A malicious server can craft sampling prompts that
instruct the LLM to include sensitive information from the conversation, tool outputs, or system
configuration in its sampling response, which is then sent back to the server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SamplingDataExfiltrationCheck(BaseCheck):
    """Data Exfiltration via Sampling."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement samp004 check logic
        return []
