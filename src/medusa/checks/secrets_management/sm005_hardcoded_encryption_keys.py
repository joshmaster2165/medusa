"""SM005: Hardcoded Encryption Keys.

Detects MCP server source code or configuration that contains hardcoded encryption keys,
initialization vectors, or salt values. Hardcoded cryptographic material makes encryption
effectively useless as the keys are available to anyone with code access.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.credential_exposure._provider_check import run_provider_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding
from medusa.utils.patterns.credentials import PROVIDER_SECRET_PATTERNS

_PATTERNS = PROVIDER_SECRET_PATTERNS["encryption"]


class HardcodedEncryptionKeysCheck(BaseCheck):
    """Hardcoded Encryption Keys."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        return run_provider_check(snapshot, self.metadata(), _PATTERNS, "Encryption key")
