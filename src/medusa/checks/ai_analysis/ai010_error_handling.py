"""AI-010: Error Handling Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiErrorHandlingCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all error_handling static checks."""

    def _category(self) -> str:
        return "error_handling"

    def _meta_file(self) -> str:
        return "ai010_error_handling"
