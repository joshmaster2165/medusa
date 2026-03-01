"""AI-020: Governance Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiGovernanceCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all governance static checks."""

    def _category(self) -> str:
        return "governance"

    def _meta_file(self) -> str:
        return "ai020_governance"
