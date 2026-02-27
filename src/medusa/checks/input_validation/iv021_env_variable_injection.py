"""IV021: Environment Variable Injection.

Detects tool parameters used to set or modify environment variables. Parameters that can
influence the process environment allow attackers to override PATH, LD_PRELOAD, and other
security-critical variables.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class EnvVariableInjectionCheck(BaseCheck):
    """Environment Variable Injection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv021 check logic
        return []
