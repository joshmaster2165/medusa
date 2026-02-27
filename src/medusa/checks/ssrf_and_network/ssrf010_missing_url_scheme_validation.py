"""SSRF010: Missing URL Scheme Validation.

Detects MCP server tools that accept URLs without validating the URL scheme or protocol. Without
scheme validation, attackers can use non-HTTP protocols such as file://, gopher://, dict://, or
ftp:// to access local files, interact with internal services, or bypass network-level
protections.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingUrlSchemeValidationCheck(BaseCheck):
    """Missing URL Scheme Validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf010 check logic
        return []
