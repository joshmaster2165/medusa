"""AI-016: Resource Security Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiResourceSecurityCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all resource_security static checks."""

    def _category(self) -> str:
        return "resource_security"

    def _meta_file(self) -> str:
        return "ai016_resource_security"
