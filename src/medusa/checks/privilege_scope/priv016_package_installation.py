"""PRIV016: Package Installation Rights.

Detects MCP tools that can install system packages (apt, yum, brew, pip install, npm install
-g). Package installation allows adding arbitrary software to the system, including malicious
packages from compromised registries.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class PackageInstallationCheck(BaseCheck):
    """Package Installation Rights."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement priv016 check logic
        return []
