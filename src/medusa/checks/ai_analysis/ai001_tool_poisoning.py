"""AI-001: Tool Poisoning Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiToolPoisoningCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all tool_poisoning static checks."""

    def _category(self) -> str:
        return "tool_poisoning"

    def _meta_file(self) -> str:
        return "ai001_tool_poisoning"
