"""TP018: JSON Injection in Parameter Defaults.

Detects serialized JSON objects embedded in parameter default values. Complex JSON defaults can
encode instructions, configuration overrides, or nested command structures that alter tool
behaviour in ways not apparent from the schema surface.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class JsonInjectionInDefaultsCheck(BaseCheck):
    """JSON Injection in Parameter Defaults."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp018 check logic
        return []
