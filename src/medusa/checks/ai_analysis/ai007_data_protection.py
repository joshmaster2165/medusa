"""AI-007: Data Protection Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiDataProtectionCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all data_protection static checks."""

    def _category(self) -> str:
        return "data_protection"

    def _meta_file(self) -> str:
        return "ai007_data_protection"
