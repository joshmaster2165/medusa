"""IV009: XML External Entity Injection Risk.

Detects tool parameters that accept XML input without restrictions on external entity
processing. XXE attacks exploit XML parsers that resolve external entities, enabling file
disclosure, SSRF, and denial of service.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class XxeInjectionCheck(BaseCheck):
    """XML External Entity Injection Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv009 check logic
        return []
