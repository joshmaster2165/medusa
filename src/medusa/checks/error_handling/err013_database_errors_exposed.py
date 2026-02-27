"""ERR013: Database Errors Exposed.

Detects MCP server error responses that include raw database error messages, SQL statements,
connection strings, or database engine error codes. These details reveal database type, schema
structure, and query logic to potential attackers.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DatabaseErrorsExposedCheck(BaseCheck):
    """Database Errors Exposed."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err013 check logic
        return []
