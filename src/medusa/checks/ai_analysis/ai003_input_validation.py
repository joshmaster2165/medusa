"""AI-003: Input Validation Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiInputValidationCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all input_validation static checks."""

    def _category(self) -> str:
        return "input_validation"

    def _meta_file(self) -> str:
        return "ai003_input_validation"
