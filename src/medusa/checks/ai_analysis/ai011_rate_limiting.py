"""AI-011: Rate Limiting Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiRateLimitingCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all rate_limiting static checks."""

    def _category(self) -> str:
        return "rate_limiting"

    def _meta_file(self) -> str:
        return "ai011_rate_limiting"
