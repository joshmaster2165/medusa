"""AUTH029: Insecure Auth Redirect.

Detects OAuth redirect URI configurations that allow open redirects. When redirect URIs are not
strictly validated, an attacker can redirect the authorization code or token to a malicious
endpoint under their control.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class InsecureAuthRedirectCheck(BaseCheck):
    """Insecure Auth Redirect."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth029 check logic
        return []
