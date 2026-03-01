"""AI-002: Authentication Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiAuthenticationCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all authentication static checks."""

    def _category(self) -> str:
        return "authentication"

    def _meta_file(self) -> str:
        return "ai002_authentication"
