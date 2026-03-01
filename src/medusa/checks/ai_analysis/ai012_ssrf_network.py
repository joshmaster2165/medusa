"""AI-012: SSRF & Network Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiSsrfNetworkCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all ssrf_and_network static checks."""

    def _category(self) -> str:
        return "ssrf_and_network"

    def _meta_file(self) -> str:
        return "ai012_ssrf_network"
