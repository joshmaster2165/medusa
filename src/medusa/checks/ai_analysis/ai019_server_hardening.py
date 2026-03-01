"""AI-019: Server Hardening Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiServerHardeningCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all server_hardening static checks."""

    def _category(self) -> str:
        return "server_hardening"

    def _meta_file(self) -> str:
        return "ai019_server_hardening"
