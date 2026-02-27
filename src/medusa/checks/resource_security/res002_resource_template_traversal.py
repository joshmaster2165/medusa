"""RES002: Resource Template Path Traversal.

Detects MCP resource templates that accept user-controlled path segments without validation,
enabling directory traversal attacks. Templates using patterns like {path} or {filename} in URI
templates can be exploited with ../ sequences to access arbitrary files.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ResourceTemplateTraversalCheck(BaseCheck):
    """Resource Template Path Traversal."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement res002 check logic
        return []
