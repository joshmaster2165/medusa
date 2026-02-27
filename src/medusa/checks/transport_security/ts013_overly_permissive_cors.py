"""TS013: Overly Permissive CORS.

Detects MCP servers with CORS configuration that allows all origins (Access-Control-Allow-
Origin: *) or reflects the request origin. Overly permissive CORS enables any website to make
authenticated requests to the MCP server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class OverlyPermissiveCorsCheck(BaseCheck):
    """Overly Permissive CORS."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ts013 check logic
        return []
