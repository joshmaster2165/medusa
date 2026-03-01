"""AI-024: Prompt Security Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiPromptSecurityCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all prompt_security static checks."""

    def _category(self) -> str:
        return "prompt_security"

    def _meta_file(self) -> str:
        return "ai024_prompt_security"
