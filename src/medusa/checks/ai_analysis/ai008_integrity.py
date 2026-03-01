"""AI-008: Integrity Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiIntegrityCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all integrity static checks."""

    def _category(self) -> str:
        return "integrity"

    def _meta_file(self) -> str:
        return "ai008_integrity"
