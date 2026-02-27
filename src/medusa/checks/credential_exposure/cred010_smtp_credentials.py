"""CRED010: SMTP Credential Exposure.

Detects email server credentials (SMTP username, password, API keys) in MCP server
configuration. SMTP credentials allow sending emails as the configured sender, enabling phishing
and spam campaigns through the organization's mail infrastructure.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.credential_exposure._provider_check import run_provider_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding
from medusa.utils.patterns.credentials import PROVIDER_SECRET_PATTERNS

_PATTERNS = PROVIDER_SECRET_PATTERNS["smtp"]


class SmtpCredentialsCheck(BaseCheck):
    """SMTP Credential Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        return run_provider_check(snapshot, self.metadata(), _PATTERNS, "SMTP")
