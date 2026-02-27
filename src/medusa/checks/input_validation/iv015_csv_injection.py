"""IV015: CSV Injection Risk.

Detects tool parameters whose output may be rendered in CSV format without sanitization.
Parameters containing formula prefixes (=, +, -, @) can execute formulas when the CSV is opened
in spreadsheet applications, enabling data exfiltration and code execution.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class CsvInjectionCheck(BaseCheck):
    """CSV Injection Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv015 check logic
        return []
