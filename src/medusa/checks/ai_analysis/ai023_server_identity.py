"""AI-023: Server Identity Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiServerIdentityCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all server_identity static checks."""

    def _category(self) -> str:
        return "server_identity"

    def _meta_file(self) -> str:
        return "ai023_server_identity"
