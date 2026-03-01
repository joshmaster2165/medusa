"""AI-014: Sampling Security Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiSamplingSecurityCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all sampling_security static checks."""

    def _category(self) -> str:
        return "sampling_security"

    def _meta_file(self) -> str:
        return "ai014_sampling_security"
