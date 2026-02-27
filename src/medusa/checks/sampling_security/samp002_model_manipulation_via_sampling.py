"""SAMP002: Model Manipulation via Sampling.

Detects MCP server configurations where sampling requests can be used to manipulate the LLM's
behavior, including altering its system prompt interpretation, overriding safety constraints, or
changing the model's decision-making process through carefully crafted sampling payloads.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ModelManipulationViaSamplingCheck(BaseCheck):
    """Model Manipulation via Sampling."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement samp002 check logic
        return []
