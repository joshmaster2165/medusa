"""IV025: Template Literal Injection.

Detects tool parameters used in JavaScript template literals or equivalent constructs without
sanitization. User input interpolated into template literals can execute arbitrary JavaScript
expressions via ${...} syntax.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class TemplateLiteralInjectionCheck(BaseCheck):
    """Template Literal Injection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv025 check logic
        return []
