"""TS016: Missing Content Security Policy.

Detects MCP server HTTP responses without Content-Security-Policy headers. CSP headers prevent
cross-site scripting, clickjacking, and other code injection attacks by restricting the sources
from which content can be loaded.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingContentSecurityPolicyCheck(BaseCheck):
    """Missing Content Security Policy."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ts016 check logic
        return []
