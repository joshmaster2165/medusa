"""AI-017: Multi-Tenant Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiMultiTenantCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all multi_tenant static checks."""

    def _category(self) -> str:
        return "multi_tenant"

    def _meta_file(self) -> str:
        return "ai017_multi_tenant"
