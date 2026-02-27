"""SSRF015: Gopher Protocol Risk.

Detects MCP server tools that accept gopher:// URLs, enabling raw TCP communication with
internal services. The gopher protocol allows sending arbitrary data to any TCP port, making it
possible to interact with Redis, SMTP, MySQL, and other internal services through the MCP tool.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class GopherProtocolRiskCheck(BaseCheck):
    """Gopher Protocol Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf015 check logic
        return []
