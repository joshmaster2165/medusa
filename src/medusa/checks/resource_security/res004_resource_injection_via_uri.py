"""RES004: Resource Injection via URI.

Detects MCP resource URIs that incorporate user input without proper sanitization, enabling
injection attacks through the URI itself. Attackers can inject special characters, protocol
handlers, or encoded payloads into resource URIs to manipulate server behavior.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ResourceInjectionViaUriCheck(BaseCheck):
    """Resource Injection via URI."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement res004 check logic
        return []
