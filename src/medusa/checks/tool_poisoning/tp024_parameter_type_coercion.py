"""TP024: Parameter Type Coercion Risk.

Detects tool parameters with loose type definitions that allow injection via type coercion.
Parameters typed as 'any', 'string | object', or using oneOf with mixed types can be exploited
by providing structured objects where strings are expected, bypassing validation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ParameterTypeCoercionCheck(BaseCheck):
    """Parameter Type Coercion Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp024 check logic
        return []
