"""CRED013: Terraform State Secrets.

Detects secrets leaked through Terraform state files referenced in MCP server configuration.
Terraform state files contain plaintext values of all managed resources, including database
passwords, API keys, and private keys.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.credential_exposure._provider_check import run_provider_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding
from medusa.utils.patterns.credentials import PROVIDER_SECRET_PATTERNS

_PATTERNS = PROVIDER_SECRET_PATTERNS["terraform"]


class TerraformStateSecretsCheck(BaseCheck):
    """Terraform State Secrets."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        return run_provider_check(snapshot, self.metadata(), _PATTERNS, "Terraform")
