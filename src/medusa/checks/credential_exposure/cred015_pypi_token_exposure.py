"""CRED015: PyPI Token Exposure.

Detects PyPI API tokens in configuration files, .pypirc, or environment variables. PyPI tokens
grant permissions to upload Python packages to the Python Package Index.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class PypiTokenExposureCheck(BaseCheck):
    """PyPI Token Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement cred015 check logic
        return []
