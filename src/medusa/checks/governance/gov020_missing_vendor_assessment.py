"""GOV020: Missing Vendor Security Assessment.

Detects MCP server deployments that use third-party MCP servers, tools, or LLM providers without
conducting vendor security assessments. Third-party vendors that process data through MCP
integrations must meet security requirements commensurate with the sensitivity of the data they
handle.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingVendorAssessmentCheck(BaseCheck):
    """Missing Vendor Security Assessment."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement gov020 check logic
        return []
