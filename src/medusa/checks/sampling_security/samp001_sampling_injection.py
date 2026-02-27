"""SAMP001: Sampling Request Injection.

Detects MCP server implementations where malicious prompts can be injected into sampling
requests sent to LLM clients. A compromised or malicious MCP server can craft sampling requests
containing hidden instructions that manipulate the LLM into performing unauthorized actions,
exfiltrating data, or bypassing safety guardrails.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SamplingInjectionCheck(BaseCheck):
    """Sampling Request Injection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement samp001 check logic
        return []
