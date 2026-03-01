"""AI-013: Agentic Behavior Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiAgenticBehaviorCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all agentic_behavior static checks."""

    def _category(self) -> str:
        return "agentic_behavior"

    def _meta_file(self) -> str:
        return "ai013_agentic_behavior"
