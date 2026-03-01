"""AI-015: Context Security Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiContextSecurityCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all context_security static checks."""

    def _category(self) -> str:
        return "context_security"

    def _meta_file(self) -> str:
        return "ai015_context_security"
