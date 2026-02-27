"""AUTH027: Weak Password Policy.

Detects MCP server authentication configurations with password requirements below security
standards. Weak password policies allow short, simple, or commonly used passwords that are
easily guessed or cracked.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class WeakPasswordPolicyCheck(BaseCheck):
    """Weak Password Policy."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth027 check logic
        return []
