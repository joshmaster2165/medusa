"""IV022: Unsafe Deserialization Risk.

Detects tool parameters that suggest object deserialization from user input. Parameters
accepting serialized objects (pickle, Java serialization, YAML load, PHP unserialize) can
trigger arbitrary code execution when attacker-controlled data is deserialized.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DeserializationRiskCheck(BaseCheck):
    """Unsafe Deserialization Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv022 check logic
        return []
