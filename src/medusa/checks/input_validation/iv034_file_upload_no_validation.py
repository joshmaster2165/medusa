"""IV034: File Upload Without Validation.

Detects file upload tool parameters without type, size, or content validation constraints.
Unrestricted file uploads allow attackers to submit malicious executables, oversized files for
denial of service, or files with double extensions to bypass type restrictions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class FileUploadNoValidationCheck(BaseCheck):
    """File Upload Without Validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv034 check logic
        return []
