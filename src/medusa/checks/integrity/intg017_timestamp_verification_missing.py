"""INTG017: Missing Timestamp Verification.

Detects signed artifacts that lack timestamp verification. Without trusted timestamps,
signatures remain valid even after the signing key has been compromised or revoked.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class TimestampVerificationMissingCheck(BaseCheck):
    """Missing Timestamp Verification."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement intg017 check logic
        return []
