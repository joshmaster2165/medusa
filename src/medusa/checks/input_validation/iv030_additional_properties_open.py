"""IV030: Open Additional Properties.

Detects tool parameter schemas that allow arbitrary additional properties beyond those
explicitly defined. Open schemas accept any extra properties, enabling injection of unexpected
parameters that may be processed by the server without validation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class AdditionalPropertiesOpenCheck(BaseCheck):
    """Open Additional Properties."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv030 check logic
        return []
