"""AI-006: Transport Security Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiTransportSecurityCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all transport_security static checks."""

    def _category(self) -> str:
        return "transport_security"

    def _meta_file(self) -> str:
        return "ai006_transport_security"
