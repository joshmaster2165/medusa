"""AI-022: Supply Chain Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiSupplyChainCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all supply_chain static checks."""

    def _category(self) -> str:
        return "supply_chain"

    def _meta_file(self) -> str:
        return "ai022_supply_chain"
