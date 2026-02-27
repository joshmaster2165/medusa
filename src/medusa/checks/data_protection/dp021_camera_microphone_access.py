"""DP021: Camera/Microphone Access.

Detects MCP tools with audio or video capture capabilities. Camera and microphone access enables
surveillance of the user's physical environment.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class CameraMicrophoneAccessCheck(BaseCheck):
    """Camera/Microphone Access."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp021 check logic
        return []
