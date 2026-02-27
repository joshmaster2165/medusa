"""SSRF020: Docker API Access.

Detects MCP server tools that can access the Docker daemon API, typically exposed on
/var/run/docker.sock (Unix socket) or TCP port 2375/2376. Access to the Docker API enables
container escape, host filesystem access, and arbitrary container creation with elevated
privileges.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DockerApiAccessCheck(BaseCheck):
    """Docker API Access."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf020 check logic
        return []
