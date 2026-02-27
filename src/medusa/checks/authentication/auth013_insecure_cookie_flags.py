"""AUTH013: Insecure Cookie Flags.

Detects authentication cookies missing security flags such as Secure, HttpOnly, and SameSite.
Cookies without these flags are vulnerable to interception over unencrypted connections, cross-
site scripting theft, and cross-site request forgery.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class InsecureCookieFlagsCheck(BaseCheck):
    """Insecure Cookie Flags."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth013 check logic
        return []
