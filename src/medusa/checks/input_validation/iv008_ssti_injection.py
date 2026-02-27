"""IV008: Server-Side Template Injection Risk.

Detects tool parameters that may be passed to server-side template engines without sanitization.
Parameters named 'template', 'content', 'message_body', or similar that accept unconstrained
strings can enable template injection in engines like Jinja2, Twig, or Handlebars.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SstiInjectionCheck(BaseCheck):
    """Server-Side Template Injection Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv008 check logic
        return []
